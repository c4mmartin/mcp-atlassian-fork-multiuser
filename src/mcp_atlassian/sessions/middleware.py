"""SessionTokenMiddleware.

Starlette middleware for extracting and validating server-issued session tokens.
Injects session data into ``request.state`` for downstream use.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from mcp_atlassian.sessions.manager import SessionManager


class SessionTokenMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, session_manager: SessionManager | None = None):
        super().__init__(app)
        self.session_manager = session_manager or SessionManager()

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Allow unauthenticated access for probes and session bootstrap.
        # (Everything else requires a server-issued session token.)
        #
        # Also allow CORS preflight (OPTIONS) requests, which browsers send before
        # authenticated POSTs when using headers like Authorization.
        if request.method == "OPTIONS":
            return await call_next(request)

        normalized_path = request.url.path.rstrip("/") or "/"
        if normalized_path == "/healthz" or normalized_path.startswith("/session"):
            return await call_next(request)

        # Extract token from Authorization header (Bearer <token>)
        auth_header = request.headers.get("Authorization")
        token: str | None = None
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()

        if not token:
            return JSONResponse(
                {"error": "Missing or invalid session token"}, status_code=401
            )

        session = await self.session_manager.get_session(token)
        if not session:
            return JSONResponse(
                {"error": "Invalid or expired session token"}, status_code=401
            )

        # Refresh TTL on activity
        await self.session_manager.refresh_session(token)

        # Inject session data into request.state
        request.state.session = session
        request.state.session_token = token

        return await call_next(request)
