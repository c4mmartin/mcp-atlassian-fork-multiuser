"""Session-related Starlette routes for MCP Atlassian."""

from __future__ import annotations

from typing import Any

from anyio import to_thread
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_atlassian.confluence import ConfluenceConfig, ConfluenceFetcher
from mcp_atlassian.jira import JiraConfig, JiraFetcher
from mcp_atlassian.sessions.manager import SessionManager

session_manager = SessionManager()


def _normalize_login_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize login payload keys for compatibility.

    Historically we used fields like `*_email` + `*_token` in examples.
    The session fetcher helpers expect either:
    - PAT: `*_personal_token` (preferred), or
    - Basic: `*_username` + `*_api_token`

    This function keeps accepting the old keys while storing canonical ones.
    """
    normalized = dict(data)

    # Confluence
    if normalized.get("confluence_email") and normalized.get("confluence_token"):
        normalized.setdefault("confluence_username", normalized["confluence_email"])
        normalized.setdefault("confluence_api_token", normalized["confluence_token"])
    if (
        normalized.get("confluence_token")
        and not normalized.get("confluence_email")
        and not normalized.get("confluence_username")
        and not normalized.get("confluence_api_token")
    ):
        normalized.setdefault(
            "confluence_personal_token", normalized["confluence_token"]
        )

    # Jira
    if normalized.get("jira_email") and normalized.get("jira_token"):
        normalized.setdefault("jira_username", normalized["jira_email"])
        normalized.setdefault("jira_api_token", normalized["jira_token"])
    if (
        normalized.get("jira_token")
        and not normalized.get("jira_email")
        and not normalized.get("jira_username")
        and not normalized.get("jira_api_token")
    ):
        normalized.setdefault("jira_personal_token", normalized["jira_token"])

    return normalized


async def validate_jira_creds(
    jira_url: str, token: str, email: str | None = None
) -> tuple[bool, str | None]:
    def _validate() -> None:
        if email:
            config = JiraConfig(
                url=jira_url,
                auth_type="basic",
                username=email,
                api_token=token,
            )
        else:
            config = JiraConfig(url=jira_url, auth_type="pat", personal_token=token)
        jira = JiraFetcher(config=config)
        jira.get_current_user_account_id()

    try:
        await to_thread.run_sync(_validate)
        return True, None
    except Exception as e:  # noqa: BLE001
        return False, str(e)


async def validate_confluence_creds(
    confluence_url: str, token: str, email: str | None = None
) -> tuple[bool, str | None]:
    def _validate() -> None:
        if email:
            config = ConfluenceConfig(
                url=confluence_url,
                auth_type="basic",
                username=email,
                api_token=token,
            )
        else:
            config = ConfluenceConfig(
                url=confluence_url,
                auth_type="pat",
                personal_token=token,
            )
        confluence = ConfluenceFetcher(config=config)
        confluence.get_current_user_info()

    try:
        await to_thread.run_sync(_validate)
        return True, None
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def register_session_routes(app: Any) -> None:
    @app.custom_route("/session/login", methods=["POST"])
    async def session_login(request: Request) -> JSONResponse:
        """Create a new session with provided credentials (no user DB).

        Accepts either canonical fields or compatibility aliases:
                - Confluence basic: confluence_url + (confluence_username +
                    confluence_api_token)
          or confluence_url + (confluence_email + confluence_token)
                - Confluence PAT: confluence_url + confluence_personal_token
                    (or confluence_token)
        - Jira basic: jira_url + (jira_username + jira_api_token)
          or jira_url + (jira_email + jira_token)
        - Jira PAT: jira_url + jira_personal_token (or jira_token)

        Returns: {"session_token": ...}
        """
        try:
            data = await request.json()
        except ValueError:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        if not isinstance(data, dict):
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        data = _normalize_login_payload(data)

        # Validate Jira credentials if present
        jira_url = data.get("jira_url")
        if isinstance(jira_url, str) and jira_url:
            jira_token = data.get("jira_personal_token") or data.get("jira_token")
            jira_user = data.get("jira_email") or data.get("jira_username")
            if isinstance(jira_token, str) and jira_token:
                ok, err = await validate_jira_creds(
                    jira_url,
                    jira_token,
                    jira_user if isinstance(jira_user, str) else None,
                )
                if not ok:
                    return JSONResponse(
                        {"error": f"Jira credential validation failed: {err}"},
                        status_code=401,
                    )
            else:
                jira_username = data.get("jira_username")
                jira_api_token = data.get("jira_api_token")
                if isinstance(jira_username, str) and isinstance(jira_api_token, str):
                    ok, err = await validate_jira_creds(
                        jira_url,
                        jira_api_token,
                        jira_username,
                    )
                    if not ok:
                        return JSONResponse(
                            {"error": f"Jira credential validation failed: {err}"},
                            status_code=401,
                        )

        # Validate Confluence credentials if present
        confluence_url = data.get("confluence_url")
        if isinstance(confluence_url, str) and confluence_url:
            confluence_token = data.get("confluence_personal_token") or data.get(
                "confluence_token"
            )
            confluence_user = data.get("confluence_email") or data.get(
                "confluence_username"
            )
            if isinstance(confluence_token, str) and confluence_token:
                ok, err = await validate_confluence_creds(
                    confluence_url,
                    confluence_token,
                    confluence_user if isinstance(confluence_user, str) else None,
                )
                if not ok:
                    return JSONResponse(
                        {
                            "error": (
                                f"Confluence credential validation failed: {err}"
                            )
                        },
                        status_code=401,
                    )
            else:
                confluence_username = data.get("confluence_username")
                confluence_api_token = data.get("confluence_api_token")
                if isinstance(confluence_username, str) and isinstance(
                    confluence_api_token, str
                ):
                    ok, err = await validate_confluence_creds(
                        confluence_url,
                        confluence_api_token,
                        confluence_username,
                    )
                    if not ok:
                        return JSONResponse(
                            {
                                "error": (
                                    f"Confluence credential validation failed: {err}"
                                )
                            },
                            status_code=401,
                        )

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
            return JSONResponse(
                {"error": "Missing or invalid session token"},
                status_code=401,
            )
        await session_manager.delete_session(token)
        return JSONResponse({"message": "Session logged out and invalidated."})
