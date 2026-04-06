import os
import httpx
import google.generativeai as genai
from fastapi import FastAPI, Request, status
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse
from dotenv import load_dotenv
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

# --- 1. Environment ---
if not os.environ.get("RENDER"):
    load_dotenv()

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'

# AI Setup
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
ai_model = genai.GenerativeModel('models/gemini-2.0-flash')

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
    https_only=True
)

# OAuth Setup
oauth = OAuth()
oauth.register(
    "auth0",
    client_id=os.getenv("AUTH0_CLIENT_ID"),
    client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email offline_access",
        # Request connection scopes for GitHub Token Vault
        "connection": "github",
        "connection_scope": "repo,read:user,user:email"
    },
    server_metadata_url=f'https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# --- 3. Token Vault: Official RFC 8693 Token Exchange ---
# This is the CORRECT Auth0 Token Vault pattern.
# We exchange the user's Auth0 access token for a GitHub access token
# via Auth0's federated connection token exchange endpoint.
# Auth0 holds and manages the GitHub token — our app never stores it directly.

async def get_github_token_via_vault(auth0_access_token: str) -> str | None:
    """
    Implements Auth0 Token Vault: Access Token Exchange (RFC 8693)
    Exchange the Auth0 access token for a GitHub token stored in Token Vault.
    Auth0 holds GitHub credentials — we request them on-demand per user action.
    """
    domain = os.getenv("AUTH0_DOMAIN")
    custom_api_client_id = os.getenv("AUTH0_CLIENT_ID")
    custom_api_client_secret = os.getenv("AUTH0_CLIENT_SECRET")

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://{domain}/oauth/token",
            json={
                "client_id": custom_api_client_id,
                "client_secret": custom_api_client_secret,
                "subject_token": auth0_access_token,
                "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
                "connection": "github"
            }
        )
        data = response.json()
        return data.get("access_token")

# Fallback: Management API approach (used if Token Vault not enabled on tenant)
async def get_github_token_fallback(user_id: str) -> str | None:
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

async def get_github_token(session_user: dict, access_token: str | None = None) -> str | None:
    """Try Token Vault first, fallback to Management API."""
    if access_token:
        token = await get_github_token_via_vault(access_token)
        if token:
            return token
    # Fallback
    return await get_github_token_fallback(session_user.get("sub"))

# --- 4. Blocked keywords for safety ---
BLOCKED_KEYWORDS = ["delete repo", "remove repo", "destroy", "drop database", "rm -rf"]

def is_blocked(prompt: str) -> bool:
    return any(kw in prompt.lower() for kw in BLOCKED_KEYWORDS)

# --- 5. Multi-step agent executor ---
async def execute_agent_action(action: str, github_token: str, github_username: str) -> dict:
    """Execute a parsed agent action against the GitHub API."""
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"token {github_token}"}

        if action.startswith("ACTION: LIST_REPOS"):
            res = await client.get(
                "https://api.github.com/user/repos?sort=pushed&direction=desc&per_page=10",
                headers=headers
            )
            repos = res.json()
            repo_list = [f"• {r['name']} ({'private' if r['private'] else 'public'}) — last push: {r['pushed_at'][:10]}" for r in repos[:8]]
            return {"status": "success", "agent_response": "Your repositories:\n" + "\n".join(repo_list)}

        elif action.startswith("ACTION: CREATE_ISSUE"):
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            title = parts[2].split(":")[1].strip()
            body = parts[3].split(":", 1)[1].strip() if len(parts) > 3 else "Created by Aegis-Agent via Auth0 Token Vault."
            res = await client.post(
                f"https://api.github.com/repos/{github_username}/{repo}/issues",
                headers=headers,
                json={"title": title, "body": body}
            )
            issue = res.json()
            return {
                "status": "success",
                "execution_trace": issue.get("html_url"),
                "reasoning_trace": f"Created issue #{issue.get('number')}: {title}"
            }

        elif action.startswith("ACTION: LIST_ISSUES"):
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            res = await client.get(
                f"https://api.github.com/repos/{github_username}/{repo}/issues?state=open",
                headers=headers
            )
            issues = res.json()
            if not issues:
                return {"status": "success", "agent_response": f"No open issues in {repo}."}
            issue_list = [f"• #{i['number']} — {i['title']}" for i in issues[:8]]
            return {"status": "success", "agent_response": f"Open issues in **{repo}**:\n" + "\n".join(issue_list)}

        elif action.startswith("ACTION: CLOSE_ISSUE"):
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            issue_number = parts[2].split(":")[1].strip()
            return {
                "status": "step_up_required",
                "message": f"⚠️ Step-up auth required: This will close issue #{issue_number} in {repo}. Type CONFIRM:{repo}:{issue_number} to proceed.",
                "pending_action": action
            }

        elif action.startswith("ACTION: CONFIRM_CLOSE"):
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            issue_number = parts[2].split(":")[1].strip()
            res = await client.patch(
                f"https://api.github.com/repos/{github_username}/{repo}/issues/{issue_number}",
                headers=headers,
                json={"state": "closed"}
            )
            return {"status": "success", "agent_response": f"✔ Issue #{issue_number} in {repo} closed successfully."}

        elif action.startswith("ACTION: CREATE_COMMENT"):
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            issue_number = parts[2].split(":")[1].strip()
            comment = parts[3].split(":", 1)[1].strip()
            await client.post(
                f"https://api.github.com/repos/{github_username}/{repo}/issues/{issue_number}/comments",
                headers=headers,
                json={"body": comment}
            )
            return {"status": "success", "agent_response": f"✔ Comment added to #{issue_number} in {repo}."}

        elif action.startswith("ACTION: REPO_STATS"):
            parts = action.split("|")
            repo = parts[1].split(":")[1].strip()
            res = await client.get(
                f"https://api.github.com/repos/{github_username}/{repo}",
                headers=headers
            )
            r = res.json()
            stats = (
                f"**{r.get('full_name')}**\n"
                f"• Description: {r.get('description') or 'No description'}\n"
                f"• Stars: {r.get('stargazers_count')} | Forks: {r.get('forks_count')} | Watchers: {r.get('watchers_count')}\n"
                f"• Language: {r.get('language') or 'Unknown'}\n"
                f"• Open Issues: {r.get('open_issues_count')}\n"
                f"• Last Push: {r.get('pushed_at', '')[:10]}\n"
                f"• URL: {r.get('html_url')}"
            )
            return {"status": "success", "agent_response": stats}

    return {"status": "error", "error": "Unknown action."}

# --- 6. Routes ---

@app.get("/")
def root_redirect():
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
    return JSONResponse({"error": "Frontend not found"}, status_code=404)

@app.get("/status")
def check_status(request: Request):
    user = request.session.get("user")
    if user:
        return {
            "status": "logged_in",
            "name": user.get("name", "User"),
            "picture": user.get("picture", ""),
            "email": user.get("email", "")
        }
    return JSONResponse({"status": "unauthorized"}, status_code=401)

@app.get("/login")
async def login(request: Request):
    return await oauth.auth0.authorize_redirect(
        request,
        redirect_uri=os.getenv("AUTH0_CALLBACK_URL"),
        connection="github",
        connection_scope="repo,read:user,user:email",
        access_type="offline"
    )

@app.get("/callback")
async def callback(request: Request):
    try:
        token = await oauth.auth0.authorize_access_token(request)
        if token.get("userinfo"):
            request.session["user"] = token.get("userinfo")
        # Store the access token in session for Token Vault exchange
        if token.get("access_token"):
            request.session["access_token"] = token.get("access_token")
        return RedirectResponse(url="/ui")
    except Exception as e:
        return JSONResponse({"error": "Login failed", "details": str(e)}, status_code=400)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/ui")

@app.get("/ask-agent")
async def ask_agent(request: Request, prompt: str):
    user = request.session.get("user")
    if not user:
        return JSONResponse({"error": "Aegis-Agent requires authorized identity to proceed."}, status_code=401)

    # Safety block
    if is_blocked(prompt):
        return {"error": "⚠️ Aegis-Agent does not perform destructive actions. Request blocked by security policy."}

    # Handle step-up confirmation
    if prompt.upper().startswith("CONFIRM:"):
        parts = prompt.split(":")
        if len(parts) >= 3:
            repo = parts[1]
            issue_num = parts[2]
            access_token = request.session.get("access_token")
            github_token = await get_github_token(user, access_token)
            if not github_token:
                return {"error": "Could not retrieve GitHub token from Token Vault."}
            async with httpx.AsyncClient() as client:
                u_res = await client.get("https://api.github.com/user", headers={"Authorization": f"token {github_token}"})
                username = u_res.json().get("login", "")
            return await execute_agent_action(
                f"ACTION: CONFIRM_CLOSE | REPO: {repo} | ISSUE: {issue_num}",
                github_token, username
            )

    # Get GitHub token from Token Vault
    access_token = request.session.get("access_token")
    github_token = await get_github_token(user, access_token)
    if not github_token:
        return {"error": "Could not retrieve GitHub token from Auth0 Token Vault."}

    # Get GitHub username
    async with httpx.AsyncClient() as client:
        u_res = await client.get("https://api.github.com/user", headers={"Authorization": f"token {github_token}"})
        github_user = u_res.json()
        github_username = github_user.get("login", "")
        # Get repos for context
        repos_res = await client.get(
            "https://api.github.com/user/repos?sort=pushed&direction=desc&per_page=5",
            headers={"Authorization": f"token {github_token}"}
        )
        repos_data = repos_res.json()
        repos_context = [f"{r['name']} (pushed: {r['pushed_at'][:10]})" for r in repos_data[:5]]

    # AI agent with full context
    context = f"""You are Aegis-Agent, a secure GitHub AI agent authenticated via Auth0 Token Vault.
User: {user.get('name')} | GitHub: @{github_username}
Recent repos: {repos_context}
Current time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

AVAILABLE ACTIONS (respond with EXACTLY this format when taking action):
- ACTION: LIST_REPOS
- ACTION: CREATE_ISSUE | REPO: <repo_name> | TITLE: <title> | BODY: <body>
- ACTION: LIST_ISSUES | REPO: <repo_name>
- ACTION: CLOSE_ISSUE | REPO: <repo_name> | ISSUE: <number>
- ACTION: CREATE_COMMENT | REPO: <repo_name> | ISSUE: <number> | COMMENT: <comment_text>
- ACTION: REPO_STATS | REPO: <repo_name>

SECURITY RULES — NEVER VIOLATE:
- NEVER delete, rename, archive, or transfer repos
- NEVER push code or modify files
- NEVER perform admin actions
- ONLY the 6 actions above are permitted write operations
- For CLOSE_ISSUE, always return the step-up action format (it requires user confirmation)
- If asked to do something outside these actions, politely refuse and explain

BEHAVIOR:
- Be concise and professional
- If task needs an action, respond with ONLY the action line, nothing else
- If just chatting, respond naturally in 1-3 sentences
- Always explain what you're doing to the user in a security-aware way"""

    ai_resp = ai_model.generate_content(context + "\n\nUser request: " + prompt).text.strip()

    # Check if AI returned an action
    for action_prefix in ["ACTION: LIST_REPOS", "ACTION: CREATE_ISSUE", "ACTION: LIST_ISSUES",
                          "ACTION: CLOSE_ISSUE", "ACTION: CREATE_COMMENT", "ACTION: REPO_STATS"]:
        if ai_resp.startswith(action_prefix):
            result = await execute_agent_action(ai_resp, github_token, github_username)
            result["reasoning_trace"] = ai_resp
            return result

    return {"agent_response": ai_resp}
