import os
import httpx
import google.generativeai as genai
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse
from dotenv import load_dotenv
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

if not os.environ.get("RENDER"):
    load_dotenv()

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'

# AI Setup
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
ai_model = genai.GenerativeModel('gemini-flash-latest')

app = FastAPI(title="Aegis-Agent")

# --- Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://aegis-agent-2.onrender.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("AUTH0_SECRET"),
    session_cookie="aegis_session",
    same_site="none", # Changed to 'none' for better cross-site support on Render
    https_only=True
)

# OAuth Setup - Added 'offline_access' for better token vault stability
oauth = OAuth()
oauth.register(
    "auth0",
    client_id=os.getenv("AUTH0_CLIENT_ID"),
    client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email repo offline_access"},
    server_metadata_url=f'https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# --- 3. The Token Vault Utility (RFC 8693) ---

async def get_github_token(user_id: str, access_token: str | None):
    domain = os.getenv("AUTH0_DOMAIN")
    client_id = os.getenv("AUTH0_CLIENT_ID")
    client_secret = os.getenv("AUTH0_CLIENT_SECRET")

    async with httpx.AsyncClient() as client:
        # 1. TRY TOKEN VAULT EXCHANGE (RFC 8693) - Primary Goal 
        if access_token:
            try:
                res = await client.post(
                    f"https://{domain}/oauth/token",
                    json={
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "subject_token": access_token,
                        "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
                        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                        "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
                        "connection": "github"
                    }
                )
                if res.status_code == 200:
                    return res.json().get("access_token")
            except Exception:
                pass

        # 2. FALLBACK: MANAGEMENT API (If exchange fails)
        try:
            token_res = await client.post(
                f"https://{domain}/oauth/token",
                json={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "audience": f"https://{domain}/api/v2/",
                    "grant_type": "client_credentials"
                }
            )
            mgmt_token = token_res.json().get("access_token")
            user_res = await client.get(
                f"https://{domain}/api/v2/users/{user_id}",
                headers={"Authorization": f"Bearer {mgmt_token}"}
            )
            for ident in user_res.json().get("identities", []):
                if ident.get("provider") == "github":
                    return ident.get("access_token")
        except Exception:
            return None
    return None

# --- 4. Routes ---

@app.get("/")
def root():
    return RedirectResponse(url="/ui")

@app.get("/ui")
def serve_ui():
    possible_paths = [
        os.path.join(os.getcwd(), "frontend", "index.html"),
        os.path.join(os.getcwd(), "..", "frontend", "index.html")
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return FileResponse(path)
    return JSONResponse({"error": "Frontend UI file not found"}, status_code=404)

@app.get("/status")
def check_status(request: Request):
    user = request.session.get("user")
    if user:
        return {"status": "logged_in", "name": user.get("name", "User")}
    return JSONResponse({"status": "unauthorized"}, status_code=401)

@app.get("/login")
async def login(request: Request):
    return await oauth.auth0.authorize_redirect(
        request, 
        redirect_uri=os.getenv("AUTH0_CALLBACK_URL"), 
        connection="github"
    )

@app.get("/callback")
async def callback(request: Request):
    try:
        token = await oauth.auth0.authorize_access_token(request)
        request.session["user"] = token.get("userinfo")
        # Store the Auth0 access token to use for the Vault exchange later
        request.session["access_token"] = token.get("access_token")
        return RedirectResponse(url="/ui")
    except Exception as e:
        return JSONResponse({"error": "Login failed", "details": str(e)}, status_code=400)

@app.get("/ask-agent")
async def ask_agent(request: Request, prompt: str):
    user = request.session.get("user")
    if not user: 
        return {"error": "Aegis-Agent requires authorized identity."}

    # Pass the Auth0 session token to the vault utility
    token = await get_github_token(user.get("sub"), request.session.get("access_token"))
    if not token:
        return {"error": "Could not retrieve GitHub vault token."}
    
    async with httpx.AsyncClient() as client:
        repos_res = await client.get(
            "https://api.github.com/user/repos?sort=pushed&per_page=5",
            headers={"Authorization": f"token {token}"}
        )
        repos_data = repos_res.json()
        repos_context = [f"{r['name']} (Activity: {r['pushed_at'][:10]})" for r in repos_data]

    context = f"""You are Aegis-Agent, a secure GitHub AI agent.
    Context: {repos_context}.
    Time: {datetime.utcnow().strftime('%Y-%m-%d')}
    
    FORMAT:
    - If acting: ACTION: CREATE_ISSUE | REPO: name | TITLE: title
    - If chatting: 1-2 professional sentences.
    """
    
    ai_resp = ai_model.generate_content(context + "\nUser Request: " + prompt).text.strip()

    # --- Robust Parser ---
    if "ACTION: CREATE_ISSUE" in ai_resp:
        try:
            parts = ai_resp.split("|")
            repo = parts[1].split(":")[1].strip()
            title = parts[2].split(":")[1].strip()
            
            async with httpx.AsyncClient() as client:
                u_res = await client.get("https://api.github.com/user", headers={"Authorization": f"token {token}"})
                username = u_res.json()['login']
                issue = await client.post(
                    f"https://api.github.com/repos/{username}/{repo}/issues",
                    headers={"Authorization": f"token {token}"},
                    json={"title": title, "body": "Generated by Aegis-Agent Identity Vault."}
                )
                return {
                    "status": "success", 
                    "execution_trace": issue.json().get("html_url"),
                    "agent_response": f"Successfully created issue in {repo}."
                }
        except Exception:
            return {"error": "Action execution failed."}

    return {"agent_response": ai_resp}