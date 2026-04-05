import os
import httpx
import google.generativeai as genai
from fastapi import FastAPI, Request, status
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse
from dotenv import load_dotenv
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware

# Only load .env if we are NOT on Render
if not os.environ.get("RENDER"):
    load_dotenv()

# Set to '0' for production (Render), '1' for local testing
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'

# AI Setup
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
ai_model = genai.GenerativeModel('models/gemini-flash-latest')

app = FastAPI(title="Aegis-Agent")

# --- MIDDLEWARE (ORDER IS CRITICAL) ---

# 1. CORS First: To handle cross-origin requests from the browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://aegis-agent-2.onrender.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Session Second: To provide request.session
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("AUTH0_SECRET"),
    session_cookie="aegis_session",
    same_site="lax",
    https_only=True # Render uses HTTPS, so this must be True
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

# --- UTILS ---
async def get_github_token(user_id: str):
    domain = os.getenv("AUTH0_DOMAIN")
    async with httpx.AsyncClient() as client:
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
        user_res = await client.get(
            f"https://{domain}/api/v2/users/{user_id}",
            headers={"Authorization": f"Bearer {mgmt_token}"}
        )
        for identity in user_res.json().get("identities", []):
            if identity.get("provider") == "github":
                return identity.get("access_token")
    return None

# --- ROUTES ---

@app.get("/")
def root_redirect():
    """Redirect main URL to UI so judges don't see a 401 error."""
    return RedirectResponse(url="/ui")

@app.get("/ui")
def serve_ui():
    """Serves the frontend. Note: Path adjusted for standard Render deployment."""
    # On Render, if your backend is in /backend and frontend is in /frontend:
    # Use the absolute path from the project root if '../' fails.
    path = os.path.join(os.getcwd(), "frontend", "index.html")
    if not os.path.exists(path):
        # Fallback for local folder structure
        path = "../frontend/index.html"
    return FileResponse(path)

@app.get("/status")
def check_status(request: Request):
    """Check if user is logged in."""
    user = request.session.get("user")
    if user:
        return {"status": "logged_in", "name": user["name"]}
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
    token = await oauth.auth0.authorize_access_token(request)
    if token.get("userinfo"):
        request.session["user"] = token.get("userinfo")
    return RedirectResponse(url="/ui")

@app.get("/ask-agent")
async def ask_agent(request: Request, prompt: str):
    user = request.session.get("user")
    if not user: 
        return {"error": "Aegis-Agent requires authorized identity to proceed."}

    token = await get_github_token(user.get("sub"))
    
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
    """
    
    ai_resp = ai_model.generate_content(context + "\nUser Request: " + prompt).text

    # Action Logic
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
                    json={"title": title, "body": "Automatically generated by Aegis-Agent."}
                )
                return {
                    "status": "success", 
                    "execution_trace": issue.json().get("html_url"),
                    "reasoning_trace": ai_resp
                }
        except Exception:
            return {"error": "Aegis-Agent encountered an error parsing the execution command."}

    return {"agent_response": ai_resp}