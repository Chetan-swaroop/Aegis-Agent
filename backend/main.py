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

# --- Simple, Clean AI Setup ---
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
ai_model = genai.GenerativeModel('gemini-flash-latest')

app = FastAPI(title="Aegis-Agent")

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
    client_kwargs={"scope": "openid profile email offline_access"},
    server_metadata_url=f'https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# --- Auth0 Token Vault (RFC 8693) ---
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
                    token = res.json().get("access_token")
                    if token:
                        return token
            except Exception:
                pass

        # Fallback: Management API
        try:
            mgmt_res = await client.post(
                f"https://{domain}/oauth/token",
                json={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "audience": f"https://{domain}/api/v2/",
                    "grant_type": "client_credentials"
                }
            )
            mgmt_token = mgmt_res.json().get("access_token")
            user_res = await client.get(
                f"https://{domain}/api/v2/users/{user.get('sub')}",
                headers={"Authorization": f"Bearer {mgmt_token}"}
            )
            for ident in user_res.json().get("identities", []):
                if ident.get("provider") == "github":
                    return ident.get("access_token")
        except Exception:
            return None

BLOCKED = ["delete repo", "remove repo", "destroy", "drop database", "rm -rf"]

async def run_action(action: str, token: str, username: str) -> dict:
    headers = {"Authorization": f"token {token}"}
    async with httpx.AsyncClient() as client:

        if action.startswith("ACTION: LIST_REPOS"):
            res = await client.get("https://api.github.com/user/repos?sort=pushed&per_page=10", headers=headers)
            repos = res.json()
            lines = [f"• {r['name']} ({'private' if r['private'] else 'public'}) — {r['pushed_at'][:10]}" for r in repos[:8]]
            return {"status": "success", "agent_response": "Your repositories:\n" + "\n".join(lines)}

        elif action.startswith("ACTION: CREATE_ISSUE"):
            parts = action.split("|")
            repo = parts[1].split(":", 1)[1].strip()
            title = parts[2].split(":", 1)[1].strip()
            body = parts[3].split(":", 1)[1].strip() if len(parts) > 3 else "Created by Aegis-Agent via Auth0 Token Vault."
            res = await client.post(
                f"https://api.github.com/repos/{username}/{repo}/issues",
                headers=headers,
                json={"title": title, "body": body}
            )
            issue = res.json()
            return {
                "status": "success",
                "execution_trace": issue.get("html_url"),
                "agent_response": f"Successfully created issue #{issue.get('number')}.",
                "reasoning_trace": f"Created issue #{issue.get('number')}: {title}"
            }

        elif action.startswith("ACTION: LIST_ISSUES"):
            parts = action.split("|")
            repo = parts[1].split(":", 1)[1].strip()
            res = await client.get(f"https://api.github.com/repos/{username}/{repo}/issues?state=open", headers=headers)
            issues = res.json()
            if not issues:
                return {"status": "success", "agent_response": f"No open issues in {repo}."}
            lines = [f"• #{i['number']} — {i['title']}" for i in issues[:8]]
            return {"status": "success", "agent_response": f"Open issues in {repo}:\n" + "\n".join(lines)}

        elif action.startswith("ACTION: CLOSE_ISSUE"):
            parts = action.split("|")
            repo = parts[1].split(":", 1)[1].strip()
            num = parts[2].split(":", 1)[1].strip()
            return {
                "status": "step_up_required",
                "message": f"⚠ Closing issue #{num} in {repo} requires confirmation. Type CONFIRM:{repo}:{num} to proceed.",
                "pending_action": action
            }

        elif action.startswith("ACTION: CONFIRM_CLOSE"):
            parts = action.split("|")
            repo = parts[1].split(":", 1)[1].strip()
            num = parts[2].split(":", 1)[1].strip()
            await client.patch(
                f"https://api.github.com/repos/{username}/{repo}/issues/{num}",
                headers=headers,
                json={"state": "closed"}
            )
            return {"status": "success", "agent_response": f"✔ Issue #{num} in {repo} closed."}

        elif action.startswith("ACTION: REPO_STATS"):
            parts = action.split("|")
            repo = parts[1].split(":", 1)[1].strip()
            res = await client.get(f"https://api.github.com/repos/{username}/{repo}", headers=headers)
            r = res.json()
            text = (
                f"{r.get('full_name')}\n"
                f"Stars: {r.get('stargazers_count')}  Forks: {r.get('forks_count')}  Open Issues: {r.get('open_issues_count')}\n"
                f"Language: {r.get('language') or 'Unknown'}\n"
                f"Last push: {r.get('pushed_at', '')[:10]}\n"
                f"URL: {r.get('html_url')}"
            )
            return {"status": "success", "agent_response": text}

    return {"status": "error", "error": "Unknown action."}

# --- Routes ---

@app.get("/")
def root():
    return RedirectResponse(url="/ui")

@app.get("/ui")
def serve_ui():
    for path in [
        os.path.join(os.getcwd(), "frontend", "index.html"),
        os.path.join(os.getcwd(), "..", "frontend", "index.html")
    ]:
        if os.path.exists(path):
            return FileResponse(path)
    return JSONResponse({"error": "Frontend not found"}, status_code=404)

@app.get("/status")
def check_status(request: Request):
    user = request.session.get("user")
    if user:
        return {
            "status": "logged_in",
            "name": user.get("name", "User"),
            "picture": user.get("picture", "")
        }
    return JSONResponse({"status": "unauthorized"}, status_code=401)

@app.get("/login")
async def login(request: Request):
    return await oauth.auth0.authorize_redirect(
        request,
        redirect_uri=os.getenv("AUTH0_CALLBACK_URL"),
        connection="github",
        connection_scope="repo,read:user,user:email"
    )

@app.get("/callback")
async def callback(request: Request):
    try:
        token = await oauth.auth0.authorize_access_token(request)
        request.session["user"] = token.get("userinfo")
        if token.get("access_token"):
            request.session["access_token"] = token.get("access_token")
        return RedirectResponse(url="/ui")
    except Exception as e:
        return JSONResponse({"error": "Login failed", "details": str(e)}, status_code=400)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/ui")

@app.get("/ask-agent")
async def ask_agent(request: Request, prompt: str):
    user = request.session.get("user")
    if not user:
        return JSONResponse({"error": "Not authenticated."}, status_code=401)

    if any(k in prompt.lower() for k in BLOCKED):
        return {"error": "⚠ Blocked: Aegis-Agent does not perform destructive actions."}

    # Handle CONFIRM step-up
    if prompt.upper().startswith("CONFIRM:"):
        parts = prompt.split(":")
        if len(parts) >= 3:
            repo, num = parts[1], parts[2]
            token = await get_github_token(user, request.session.get("access_token"))
            if not token:
                return {"error": "Could not retrieve token from vault."}
            async with httpx.AsyncClient() as c:
                u = await c.get("https://api.github.com/user", headers={"Authorization": f"token {token}"})
                username = u.json().get("login", "")
            return await run_action(f"ACTION: CONFIRM_CLOSE | REPO: {repo} | ISSUE: {num}", token, username)

    token = await get_github_token(user, request.session.get("access_token"))
    if not token:
        return {"error": "Could not retrieve GitHub token from Auth0 Token Vault."}

    async with httpx.AsyncClient() as c:
        u = await c.get("https://api.github.com/user", headers={"Authorization": f"token {token}"})
        github_user = u.json()
        username = github_user.get("login", "")
        repos_res = await c.get(
            "https://api.github.com/user/repos?sort=pushed&per_page=5",
            headers={"Authorization": f"token {token}"}
        )
        repos_data = repos_res.json()
        repos = [f"{r['name']} (Last pushed: {r.get('pushed_at', 'Unknown')[:10]})" for r in repos_data[:5]]

    context = f"""You are Aegis-Agent, a secure GitHub AI agent. Auth0 Token Vault handles all credentials.
User: {user.get('name')} | GitHub: @{username}
Recent repos: {repos}
Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

ACTIONS — reply with EXACTLY this format when taking action, nothing else:
- ACTION: LIST_REPOS
- ACTION: CREATE_ISSUE | REPO: name | TITLE: title | BODY: description
- ACTION: LIST_ISSUES | REPO: name
- ACTION: CLOSE_ISSUE | REPO: name | ISSUE: number
- ACTION: REPO_STATS | REPO: name

RULES:
- Never delete, push code, or do admin actions
- For chat/questions reply naturally in 1-3 sentences
- If action needed, reply with ONLY the action line"""

    try:
        ai_resp = ai_model.generate_content(context + "\n\nUser: " + prompt).text.strip()
    except Exception as e:
        err = str(e)
        if "quota" in err.lower() or "429" in err or "exhausted" in err.lower():
            return {"status": "rate_limited", "agent_response": "[SYSTEM OVERLOAD] Aegis-Agent API quota exhausted. Please wait 60 seconds."}
        return {"error": f"AI error: {err}"}

    # --- Robust Parser ---
    action_line = None
    for line in ai_resp.split('\n'):
        cleaned_line = line.replace("`", "").replace("*", "").replace("- ", "").strip()
        if cleaned_line.startswith("ACTION:"):
            action_line = cleaned_line
            break

    if action_line:
        for prefix in ["ACTION: LIST_REPOS", "ACTION: CREATE_ISSUE", "ACTION: LIST_ISSUES",
                       "ACTION: CLOSE_ISSUE", "ACTION: REPO_STATS"]:
            if action_line.startswith(prefix):
                result = await run_action(action_line, token, username)
                result["reasoning_trace"] = action_line
                return result

    return {"agent_response": ai_resp}