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
import itertools

# --- 1. Environment & API Rotation Setup ---
if not os.environ.get("RENDER"):
    load_dotenv()

# Set to '0' for Production (HTTPS required), '1' for Local (HTTP allowed)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'

_raw_keys = [
    os.getenv("GEMINI_API_KEY"),
    os.getenv("GEMINI_API_KEY_2"),
    os.getenv("GEMINI_API_KEY_3"),
    os.getenv("GEMINI_API_KEY_4"),
    os.getenv("GEMINI_API_KEY_5"),
]
GEMINI_KEYS = [k for k in _raw_keys if k]
_key_cycle = itertools.cycle(GEMINI_KEYS)

def get_ai_model():
    key = next(_key_cycle)
    genai.configure(api_key=key)
    # Using 'latest' for the most stable endpoint
    return genai.GenerativeModel('models/gemini-1.5-flash-latest')

def call_ai(prompt: str) -> str:
    """Tries each API key in the rotation if one hits a rate limit."""
    last_error = None
    for _ in range(len(GEMINI_KEYS)):
        try:
            model = get_ai_model()
            return model.generate_content(prompt).text.strip()
        except Exception as e:
            last_error = e
            if any(x in str(e).lower() for x in ["429", "quota", "exhausted"]):
                continue
            raise e
    raise Exception(f"All AI Quotas exhausted. Last error: {last_error}")

app = FastAPI(title="Aegis-Agent")

# --- 2. Middleware ---
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
    https_only=True,
    max_age=3600
)

oauth = OAuth()
oauth.register(
    "auth0",
    client_id=os.getenv("AUTH0_CLIENT_ID"),
    client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email repo offline_access"},
    server_metadata_url=f'https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# --- 3. Token Vault (RFC 8693) ---
async def get_github_token(user: dict, access_token: str | None) -> str | None:
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
            except Exception: pass

        # Fallback: Management API
        try:
            m_res = await client.post(
                f"https://{domain}/oauth/token",
                json={"client_id": client_id, "client_secret": client_secret,
                      "audience": f"https://{domain}/api/v2/", "grant_type": "client_credentials"}
            )
            m_token = m_res.json().get("access_token")
            u_res = await client.get(f"https://{domain}/api/v2/users/{user.get('sub')}", 
                                    headers={"Authorization": f"Bearer {m_token}"})
            for ident in u_res.json().get("identities", []):
                if ident.get("provider") == "github": return ident.get("access_token")
        except Exception: return None
    return None

# --- 4. Premium Agent Actions (Detailed Friendly Output) ---
async def run_action(action: str, token: str, username: str) -> dict:
    headers = {"Authorization": f"token {token}"}
    async with httpx.AsyncClient() as client:
        
        # 1. LIST_REPOS
        if "ACTION: LIST_REPOS" in action:
            res = await client.get("https://api.github.com/user/repos?sort=pushed&per_page=5", headers=headers)
            repos = res.json()
            names = [f"{r['name']} ({r['pushed_at'][:10]})" for r in repos]
            detailed_msg = f"Your most recently active repositories from the vault are {', '.join(names[:-1])}, and {names[-1]}."
            return {"status": "success", "agent_response": detailed_msg, "reasoning_trace": action}

        # 2. CREATE_ISSUE
        elif "ACTION: CREATE_ISSUE" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            title = parts[2].split(":")[1].strip()
            res = await client.post(f"https://api.github.com/repos/{username}/{repo}/issues", 
                                    headers=headers, json={"title": title, "body": "Logged via Aegis-Agent."})
            issue = res.json()
            return {"status": "success", "execution_trace": issue.get("html_url"), 
                    "agent_response": f"Successfully created issue #{issue.get('number')} in **{repo}**. The federated token has been discarded.",
                    "reasoning_trace": action}

        # 3. LIST_ISSUES
        elif "ACTION: LIST_ISSUES" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            res = await client.get(f"https://api.github.com/repos/{username}/{repo}/issues?state=open", headers=headers)
            issues = res.json()
            if not issues: return {"status": "success", "agent_response": f"No open issues in **{repo}**.", "reasoning_trace": action}
            issue_list = "\n".join([f"• #{i['number']}: {i['title']}" for i in issues[:5]])
            return {"status": "success", "agent_response": f"Open issues in **{repo}**:\n\n{issue_list}", "reasoning_trace": action}

        # 4. CLOSE_ISSUE (Step-Up Auth)
        elif "ACTION: CLOSE_ISSUE" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            num = parts[2].split(":")[1].strip()
            detailed_msg = f"⚠ **Security Protocol**: Closing issue #{num} in {repo} is a destructive action. Type: `CONFIRM:{repo}:{num}`"
            return {"status": "step_up_required", "message": detailed_msg, "pending_action": action}

        # 5. REPO_STATS
        elif "ACTION: REPO_STATS" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            res = await client.get(f"https://api.github.com/repos/{username}/{repo}", headers=headers)
            r = res.json()
            detailed_msg = f"Metrics for **{repo}**:\nStars: **{r['stargazers_count']}** | Language: **{r['language']}** | Open Issues: **{r['open_issues_count']}**."
            return {"status": "success", "agent_response": detailed_msg, "reasoning_trace": action}

        # 6. COMMENT_ISSUE
        elif "ACTION: COMMENT_ISSUE" in action:
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            num = parts[2].split(":")[1].strip()
            msg = parts[3].split(":")[1].strip()
            await client.post(f"https://api.github.com/repos/{username}/{repo}/issues/{num}/comments", headers=headers, json={"body": msg})
            return {"status": "success", "agent_response": f"Comment securely posted to issue #{num} in **{repo}**.", "reasoning_trace": action}

    return {"status": "error", "error": "Vault action failed."}

# --- 5. Routes ---

@app.get("/")
def root(): return RedirectResponse(url="/ui")

@app.get("/ui")
def serve_ui():
    for path in [os.path.join(os.getcwd(), "frontend", "index.html"), os.path.join(os.getcwd(), "..", "frontend", "index.html")]:
        if os.path.exists(path): return FileResponse(path)
    return JSONResponse({"error": "UI Not Found"}, status_code=404)

@app.get("/status")
def check_status(request: Request):
    user = request.session.get("user")
    if user: 
        # Requirement 1: Return key count and picture for the new UI
        return {
            "status": "logged_in", 
            "name": user.get("name", "User"), 
            "picture": user.get("picture", ""),
            "keys": len(GEMINI_KEYS)
        }
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
    except Exception as e: return JSONResponse({"error": str(e)}, status_code=400)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/ui")

@app.get("/ask-agent")
async def ask_agent(request: Request, prompt: str):
    user = request.session.get("user")
    if not user: return JSONResponse({"error": "Unauthorized"}, status_code=401)

    # Handle CONFIRM Step-up Auth
    if prompt.upper().startswith("CONFIRM:"):
        parts = prompt.split(":")
        repo, num = parts[1], parts[2]
        token = await get_github_token(user, request.session.get("access_token"))
        async with httpx.AsyncClient() as c:
            u_res = await c.get("https://api.github.com/user", headers={"Authorization": f"token {token}"})
            username = u_res.json()['login']
            await c.patch(f"https://api.github.com/repos/{username}/{repo}/issues/{num}", 
                         headers={"Authorization": f"token {token}"}, json={"state": "closed"})
            return {"status": "success", "agent_response": f"✔ SECURE CLOSE COMPLETE: Issue #{num} in {repo} is now closed.", "reasoning_trace": "ACTION: CONFIRM_CLOSE"}

    token = await get_github_token(user, request.session.get("access_token"))
    async with httpx.AsyncClient() as c:
        u_res = await c.get("https://api.github.com/user", headers={"Authorization": f"token {token}"})
        username = u_res.json()['login']
        repos_res = await c.get("https://api.github.com/user/repos?sort=pushed&per_page=5", headers={"Authorization": f"token {token}"})
        repos_context = [f"{r['name']} ({r['pushed_at'][:10]})" for r in repos_res.json()]

    context = f"""You are Aegis-Agent. Time: {datetime.utcnow().strftime('%Y-%m-%d')} | User: @{username}
    Repos: {repos_context}
    
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

    try:
        ai_resp = call_ai(context + "\nUser: " + prompt)
    except Exception as e: return {"error": str(e)}

    # Robust Action Execution
    for line in ai_resp.split('\n'):
        cleaned = line.replace("- ", "").strip()
        if cleaned.startswith("ACTION:"):
            # Requirement 2: Ensure reasoning_trace is returned for the Audit Log
            result = await run_action(cleaned, token, username)
            if "reasoning_trace" not in result: result["reasoning_trace"] = cleaned
            return result

    return {"agent_response": ai_resp}