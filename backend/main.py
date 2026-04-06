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

# --- 1. Token Vault Utility (RFC 8693) ---
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
                if res.status_code == 200:
                    return res.json().get("access_token")
            except Exception:
                pass
        
        # Fallback: Management API
        try:
            token_res = await client.post(
                f"https://{domain}/oauth/token",
                json={
                    "client_id": client_id, "client_secret": client_secret,
                    "audience": f"https://{domain}/api/v2/", "grant_type": "client_credentials"
                }
            )
            m_token = token_res.json().get("access_token")
            u_res = await client.get(f"https://{domain}/api/v2/users/{user_id}", headers={"Authorization": f"Bearer {m_token}"})
            for ident in u_res.json().get("identities", []):
                if ident.get("provider") == "github": return ident.get("access_token")
        except Exception: return None
    return None

# --- 2. Detailed Agent Actions (The Hands) ---
async def run_action(action: str, token: str, username: str) -> dict:
    headers = {"Authorization": f"token {token}"}
    async with httpx.AsyncClient() as client:
        
        # 1. LIST_REPOS
        if "ACTION: LIST_REPOS" in action:
            res = await client.get("https://api.github.com/user/repos?sort=pushed&per_page=5", headers=headers)
            repos = res.json()
            names = [f"{r['name']} ({r['pushed_at'][:10]})" for r in repos]
            detailed_msg = f"Your most recently active repositories from the vault are {', '.join(names[:-1])}, and {names[-1]}. These represent your latest projects with activity as of today."
            return {"status": "success", "agent_response": detailed_msg}

        # 2. CREATE_ISSUE
        if "ACTION: CREATE_ISSUE" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            title = parts[2].split(":")[1].strip()
            res = await client.post(f"https://api.github.com/repos/{username}/{repo}/issues", headers=headers, json={"title": title})
            issue = res.json()
            detailed_msg = f"I've successfully opened a new issue in **{repo}** titled '{title}'. You can track its progress via the execution link below."
            return {"status": "success", "execution_trace": issue.get("html_url"), "agent_response": detailed_msg}

        # 3. LIST_ISSUES
        if "ACTION: LIST_ISSUES" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            res = await client.get(f"https://api.github.com/repos/{username}/{repo}/issues?state=open", headers=headers)
            issues = res.json()
            if not issues: return {"status": "success", "agent_response": f"I checked **{repo}** and found no open issues. Everything looks clear!"}
            issue_list = "\n".join([f"• #{i['number']}: {i['title']}" for i in issues[:5]])
            return {"status": "success", "agent_response": f"Found {len(issues)} open issues in **{repo}**:\n\n{issue_list}"}

        # 4. CLOSE_ISSUE (Step-Up Auth Trigger)
        if "ACTION: CLOSE_ISSUE" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            num = parts[2].split(":")[1].strip()
            detailed_msg = f"⚠ **Security Protocol**: Closing issue #{num} in {repo} is a destructive action. To ensure user control, please manually authorize this by typing: `CONFIRM:{repo}:{num}`"
            return {"status": "step_up_required", "message": detailed_msg, "pending_action": action}

        # 5. REPO_STATS
        if "ACTION: REPO_STATS" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            res = await client.get(f"https://api.github.com/repos/{username}/{repo}", headers=headers)
            r = res.json()
            detailed_msg = f"I've retrieved metrics for **{repo}**.\n\nStars: **{r['stargazers_count']}** | Language: **{r['language']}** | Open Issues: **{r['open_issues_count']}**\nLast push recorded: {r['pushed_at'][:10]}."
            return {"status": "success", "agent_response": detailed_msg}

        # 6. COMMENT_ISSUE
        if "ACTION: COMMENT_ISSUE" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            num = parts[2].split(":")[1].strip()
            msg = parts[3].split(":")[1].strip()
            await client.post(f"https://api.github.com/repos/{username}/{repo}/issues/{num}/comments", headers=headers, json={"body": msg})
            return {"status": "success", "agent_response": f"Your comment has been securely posted to issue #{num} in **{repo}**."}

    return {"status": "error", "error": "Vault action failed."}

# --- 3. Routes ---

@app.get("/")
def root(): return RedirectResponse(url="/ui")

@app.get("/ui")
def serve_ui():
    for path in [os.path.join(os.getcwd(), "frontend", "index.html"), os.path.join(os.getcwd(), "..", "frontend", "index.html")]:
        if os.path.exists(path): return FileResponse(path)
    return JSONResponse({"error": "UI not found"}, status_code=404)

@app.get("/status")
def check_status(request: Request):
    user = request.session.get("user")
    if user: return {"status": "logged_in", "name": user.get("name", "User")}
    return JSONResponse({"status": "unauthorized"}, status_code=401)

@app.get("/login")
async def login(request: Request):
    return await oauth.auth0.authorize_redirect(request, redirect_uri=os.getenv("AUTH0_CALLBACK_URL"), connection="github")

@app.get("/callback")
async def callback(request: Request):
    try:
        token = await oauth.auth0.authorize_access_token(request)
        request.session["user"] = token.get("userinfo")
        request.session["access_token"] = token.get("access_token")
        return RedirectResponse(url="/ui")
    except Exception as e: return JSONResponse({"error": "Login failed", "details": str(e)}, status_code=400)

@app.get("/ask-agent")
async def ask_agent(request: Request, prompt: str):
    user = request.session.get("user")
    if not user: return {"error": "Authentication required."}

    # --- STEP-UP AUTH LOGIC ---
    if prompt.upper().startswith("CONFIRM:"):
        parts = prompt.split(":")
        repo, num = parts[1], parts[2]
        token = await get_github_token(user.get("sub"), request.session.get("access_token"))
        async with httpx.AsyncClient() as c:
            u = await c.get("https://api.github.com/user", headers={"Authorization": f"token {token}"})
            username = u.json()['login']
            await c.patch(f"https://api.github.com/repos/{username}/{repo}/issues/{num}", headers={"Authorization": f"token {token}"}, json={"state": "closed"})
            return {"status": "success", "agent_response": f"✔ SECURE CLOSE COMPLETE: Issue #{num} in {repo} is now closed."}

    token = await get_github_token(user.get("sub"), request.session.get("access_token"))
    async with httpx.AsyncClient() as client:
        u_res = await client.get("https://api.github.com/user", headers={"Authorization": f"token {token}"})
        username = u_res.json()['login']
        repos_res = await client.get("https://api.github.com/user/repos?sort=pushed&per_page=5", headers={"Authorization": f"token {token}"})
        repos_context = [f"{r['name']} ({r['pushed_at'][:10]})" for r in repos_res.json()]

    context = f"""You are Aegis-Agent. User: {username}. Repos: {repos_context}.
    ACTIONS:
    ACTION: LIST_REPOS
    ACTION: CREATE_ISSUE | REPO: name | TITLE: title
    ACTION: LIST_ISSUES | REPO: name
    ACTION: CLOSE_ISSUE | REPO: name | ISSUE: number
    ACTION: REPO_STATS | REPO: name
    ACTION: COMMENT_ISSUE | REPO: name | ISSUE: number | MSG: text

    RULES:
    - If user wants an action, reply with ONLY the ACTION line.
    - Otherwise, chat naturally in 1-2 sentences."""

    ai_resp = ai_model.generate_content(context + "\nUser: " + prompt).text.strip()

    # Robust Parser
    action_line = None
    for line in ai_resp.split('\n'):
        cleaned = line.replace("- ", "").strip()
        if cleaned.startswith("ACTION:"):
            action_line = cleaned
            break

    if action_line:
        res = await run_action(action_line, token, username)
        res["reasoning_trace"] = action_line
        return res

    return {"agent_response": ai_resp}