import os
import httpx
import google.generativeai as genai
from fastapi import FastAPI, Request, status
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse
from dotenv import load_dotenv
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware

# --- 1. Environment Handling ---
# Only load .env if NOT on Render. This prevents local 'localhost' links 
# from breaking your production 'aegis-agent-2' settings.
if not os.environ.get("RENDER"):
    load_dotenv()

# Set to '0' for production (Render), '1' for local testing
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'

# AI Setup
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
ai_model = genai.GenerativeModel('models/gemini-flash-latest')

app = FastAPI(title="Aegis-Agent")

# --- 2. Middleware Stack (Order is Critical) ---

# CORS First
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://aegis-agent-2.onrender.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Session Middleware Second
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("AUTH0_SECRET"),
    session_cookie="aegis_session",
    same_site="lax",
    https_only=True # Required for Render's HTTPS
)

# OAuth Setup
oauth = OAuth()
oauth.register(
    "auth0",
    client_id=os.getenv("AUTH0_CLIENT_ID"),
    client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email repo"},
    server_metadata_url=f'https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# --- 3. Utilities ---

async def get_github_token(user_id: str):
    domain = os.getenv("AUTH0_DOMAIN")
    async with httpx.AsyncClient() as client:
        # Get Management API token
        token_res = await client.post(
            f"https://{domain}/oauth/token",
            json={
                "client_id": os.getenv("AUTH0_CLIENT_ID"),
                "client_secret": os.getenv("AUTH0_CLIENT_SECRET"),
                "audience": f"https://{domain}/api/v2/",
                "grant_type": "client_credentials"
            }
        )
        mgmt_token = token_res.json().get("access_token")
        
        # Fetch GitHub identity from Auth0
        user_res = await client.get(
            f"https://{domain}/api/v2/users/{user_id}",
            headers={"Authorization": f"Bearer {mgmt_token}"}
        )
        for identity in user_res.json().get("identities", []):
            if identity.get("provider") == "github":
                return identity.get("access_token")
    return None

# --- 4. Routes ---

@app.get("/")
def root_redirect():
    """Safety redirect so judges don't hit a 401 on the root URL."""
    return RedirectResponse(url="/ui")

@app.get("/ui")
def serve_ui():
    """Robust path finding for the frontend file."""
    # Try looking in the current folder, then the parent (covers local and Render)
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
    # This sends the user to Auth0 and specifically requests GitHub
    return await oauth.auth0.authorize_redirect(
        request, 
        redirect_uri=os.getenv("AUTH0_CALLBACK_URL"), 
        connection="github"
    )

@app.get("/callback")
async def callback(request: Request):
    """The secure return point for the identity shield."""
    try:
        token = await oauth.auth0.authorize_access_token(request)
        if token.get("userinfo"):
            request.session["user"] = token.get("userinfo")
        return RedirectResponse(url="/ui")
    except Exception as e:
        return JSONResponse({"error": "Login failed", "details": str(e)}, status_code=400)

@app.get("/ask-agent")
async def ask_agent(request: Request, prompt: str):
    user = request.session.get("user")
    if not user: 
        return {"error": "Aegis-Agent requires authorized identity to proceed."}

    token = await get_github_token(user.get("sub"))
    if not token:
        return {"error": "Could not retrieve GitHub vault token."}
    
    async with httpx.AsyncClient() as client:
        repos_res = await client.get(
            "https://api.github.com/user/repos?sort=pushed&direction=desc",
            headers={"Authorization": f"token {token}"}
        )
        repos_data = repos_res.json()
        repos_context = [f"{r['name']} (Last activity: {r['pushed_at']})" for r in repos_data[:5]]

    context = f"""
    You are Aegis-Agent, a high-security GitHub Execution Assistant. 
    User's current repository context: {repos_context}.
    You operate within a secure identity shield powered by Auth0.
    
    INSTRUCTIONS:
    - If task involves repo changes, use ACTION: CREATE_ISSUE | REPO: name | TITLE: title
    - Otherwise, chat naturally.
    """
    
    ai_resp = ai_model.generate_content(context + "\nUser Request: " + prompt).text

    if "ACTION: CREATE_ISSUE" in ai_resp:
        try:
            parts = ai_resp.split("|")
            repo = parts[1].split(":")[1].strip()
            title = parts[2].split(":")[1].strip()
            
            async with httpx.AsyncClient() as client:
                u_res = await client.get("https://api.github.com/user", headers={"Authorization": f"token {token}"})
                issue = await client.post(
                    f"https://api.github.com/repos/{u_res.json()['login']}/{repo}/issues",
                    headers={"Authorization": f"token {token}"},
                    json={"title": title, "body": "Generated by Aegis-Agent Identity Vault."}
                )
                return {
                    "status": "success", 
                    "execution_trace": issue.json().get("html_url"),
                    "reasoning_trace": ai_resp
                }
        except Exception:
            return {"error": "Aegis-Agent parsing failure."}

    return {"agent_response": ai_resp}