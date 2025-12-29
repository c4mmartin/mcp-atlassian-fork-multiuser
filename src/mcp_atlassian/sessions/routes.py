"""
Session-related Starlette routes for MCP Atlassian.
"""
from starlette.requests import Request
from starlette.responses import JSONResponse
from mcp_atlassian.sessions.manager import SessionManager
from mcp_atlassian.jira.client import JiraClient
from mcp_atlassian.confluence.client import ConfluenceClient

session_manager = SessionManager()

async def validate_jira_creds(jira_url, token, email=None):
    try:
        client = JiraClient(
            url=jira_url,
            api_token=token,
            email=email,
        )
        await client.get_myself()
        return True, None
    except Exception as e:
        return False, str(e)

async def validate_confluence_creds(confluence_url, token, email=None):
    try:
        client = ConfluenceClient(
            url=confluence_url,
            api_token=token,
            email=email,
        )
        await client.get_current_user()
        return True, None
    except Exception as e:
        return False, str(e)

def register_session_routes(app):
    @app.custom_route("/session/login", methods=["POST"])
    async def session_login(request: Request) -> JSONResponse:
        """Create a new session with provided credentials (no user DB).
        Expects JSON: {"jira_token": ..., "confluence_token": ..., ...}
        Returns: {"session_token": ...}
        """
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)
        # Validate Jira credentials if present
        if "jira_token" in data and "jira_url" in data:
            ok, err = await validate_jira_creds(data["jira_url"], data["jira_token"], data.get("jira_email"))
            if not ok:
                return JSONResponse({"error": f"Jira credential validation failed: {err}"}, status_code=401)
        # Validate Confluence credentials if present
        if "confluence_token" in data and "confluence_url" in data:
            ok, err = await validate_confluence_creds(data["confluence_url"], data["confluence_token"], data.get("confluence_email"))
            if not ok:
                return JSONResponse({"error": f"Confluence credential validation failed: {err}"}, status_code=401)
        session_token = await session_manager.create_session(data)
        return JSONResponse({"session_token": session_token})

    @app.custom_route("/session/logout", methods=["POST"])
    async def session_logout(request: Request) -> JSONResponse:
        """Invalidate the current session by deleting it from Redis."""
        auth_header = request.headers.get("Authorization")
        token = None
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return JSONResponse({"error": "Missing or invalid session token"}, status_code=401)
        await session_manager.delete_session(token)
        return JSONResponse({"message": "Session logged out and invalidated."})
