"""
SessionManager: Handles session creation, validation, and isolation for MCP Atlassian.
Integrates with RedisManager for storage and FastAPI for web integration.
"""
import secrets
from typing import Any, Optional
from mcp_atlassian.sessions.db_manager import RedisManager

class SessionManager:
    """Manages user sessions using Redis as backend."""
    def __init__(self, redis_manager: Optional[RedisManager] = None, ttl: int = 3600):
        self.redis = redis_manager or RedisManager()
        self.ttl = ttl

    async def create_session(self, data: dict[str, Any]) -> str:
        """Create a new session and return its token.

        Args:
            data (dict): Session data (credentials, context, etc).
        Returns:
            str: Opaque session token.
        """
        session_id = secrets.token_urlsafe(32)
        await self.redis.set_session(session_id, data, ttl=self.ttl)
        return session_id

    async def get_session(self, session_id: str) -> Optional[dict[str, Any]]:
        """Retrieve session data by session token.

        Args:
            session_id (str): Session token.
        Returns:
            dict or None: Session data if found, else None.
        """
        return await self.redis.get_session(session_id)

    async def delete_session(self, session_id: str):
        """Delete a session by token."""
        await self.redis.delete_session(session_id)

    async def refresh_session(self, session_id: str):
        """Refresh session TTL on activity."""
        await self.redis.refresh_session(session_id, ttl=self.ttl)

    async def session_exists(self, session_id: str) -> bool:
        """Check if a session exists."""
        return await self.redis.session_exists(session_id)
