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

# Middleware
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
    same_site="none",
    https_only=True
)

oauth = OAuth()
oauth.register(
    "auth0",
    client_id=os.getenv("AUTH0_CLIENT_ID"),
    client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email repo offline_access"},
    server_metadata_url=f'https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# --- 1. Token Vault (RFC 8693) ---
async def get_github_token(user_id: str, access_token: str | None):
    domain = os.getenv("AUTH0_DOMAIN")
    client_id = os.getenv("AUTH0_CLIENT_ID")
    client_secret = os.getenv("AUTH0_CLIENT_SECRET")
    async with httpx.AsyncClient() as client:
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
                if res.status_code == 200: return res.json().get("access_token")
            except Exception: pass
        return None # Simplified for brevity, add Management API fallback if needed

# --- 2. The 6 Agent Actions (The Hands) ---
async def run_action(action: str, token: str, username: str) -> dict:
    headers = {"Authorization": f"token {token}"}
    async with httpx.AsyncClient() as client:
        
        # 1. LIST_REPOS
        if "ACTION: LIST_REPOS" in action:
            res = await client.get("https://api.github.com/user/repos?sort=pushed&per_page=5", headers=headers)
            repos = [f"• {r['name']} ({r['pushed_at'][:10]})" for r in res.json()]
            return {"status": "success", "agent_response": "Found your latest repos:\n" + "\n".join(repos)}

        # 2. CREATE_ISSUE
        if "ACTION: CREATE_ISSUE" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            title = parts[2].split(":")[1].strip()
            res = await client.post(f"https://api.github.com/repos/{username}/{repo}/issues", headers=headers, json={"title": title})
            return {"status": "success", "execution_trace": res.json().get("html_url"), "agent_response": f"Issue created in {repo}."}

        # 3. LIST_ISSUES
        if "ACTION: LIST_ISSUES" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            res = await client.get(f"https://api.github.com/repos/{username}/{repo}/issues", headers=headers)
            issues = [f"• #{i['number']}: {i['title']}" for i in res.json()[:5]]
            return {"status": "success", "agent_response": f"Open issues in {repo}:\n" + "\n".join(issues)}

        # 4. CLOSE_ISSUE (Step-Up Auth Trigger)
        if "ACTION: CLOSE_ISSUE" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            num = parts[2].split(":")[1].strip()
            return {
                "status": "step_up_required",
                "message": f"⚠ Security: Closing issue #{num} in {repo} requires manual confirmation. Type 'CONFIRM:{repo}:{num}' to proceed.",
                "pending_action": action
            }

        # 5. REPO_STATS
        if "ACTION: REPO_STATS" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            res = await client.get(f"https://api.github.com/repos/{username}/{repo}", headers=headers)
            r = res.json()
            stats = f"📊 {repo} Stats:\nStars: {r['stargazers_count']} | Language: {r['language']} | Forks: {r['forks_count']}"
            return {"status": "success", "agent_response": stats}

        # 6. COMMENT_ISSUE
        if "ACTION: COMMENT_ISSUE" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            num = parts[2].split(":")[1].strip()
            msg = parts[3].split(":")[1].strip()
            await client.post(f"https://api.github.com/repos/{username}/{repo}/issues/{num}/comments", headers=headers, json={"body": msg})
            return {"status": "success", "agent_response": f"Comment added to issue #{num}."}

    return {"status": "error", "error": "Action execution failed."}

# --- 3. Routes ---

@app.get("/ask-agent")
async def ask_agent(request: Request, prompt: str):
    user = request.session.get("user")
    if not user: return {"error": "Unauthorized"}

    # --- STEP-UP AUTH LOGIC (The CONFIRM handler) ---
    if prompt.upper().startswith("CONFIRM:"):
        parts = prompt.split(":")
        repo, num = parts[1], parts[2]
        token = await get_github_token(user.get("sub"), request.session.get("access_token"))
        async with httpx.AsyncClient() as c:
            u = await c.get("https://api.github.com/user", headers={"Authorization": f"token {token}"})
            username = u.json()['login']
            await c.patch(f"https://api.github.com/repos/{username}/{repo}/issues/{num}", headers={"Authorization": f"token {token}"}, json={"state": "closed"})
            return {"status": "success", "agent_response": f"✔ Issue #{num} in {repo} has been closed securely."}

    token = await get_github_token(user.get("sub"), request.session.get("access_token"))
    async with httpx.AsyncClient() as client:
        u_res = await client.get("https://api.github.com/user", headers={"Authorization": f"token {token}"})
        username = u_res.json()['login']

    context = f"""You are Aegis-Agent. 
    Time: {datetime.utcnow().strftime('%Y-%m-%d')} | User: {username}
    
    ACTIONS:
    ACTION: LIST_REPOS
    ACTION: CREATE_ISSUE | REPO: name | TITLE: title
    ACTION: LIST_ISSUES | REPO: name
    ACTION: CLOSE_ISSUE | REPO: name | ISSUE: number
    ACTION: REPO_STATS | REPO: name
    ACTION: COMMENT_ISSUE | REPO: name | ISSUE: number | MSG: text

    RULES:
    - If user wants an action, reply with ONLY the ACTION line.
    - Close issue is a destructive action; trigger CLOSE_ISSUE format.
    - Otherwise, be a helpful security-focused assistant."""

    ai_resp = ai_model.generate_content(context + "\nUser: " + prompt).text.strip()

    # Simple Parsing
    for line in ai_resp.split('\n'):
        if "ACTION:" in line:
            res = await run_action(line, token, username)
            res["reasoning_trace"] = line
            return res

    return {"agent_response": ai_resp}

# (Keep your /, /ui, /login, /callback, /status routes as they were)