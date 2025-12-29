"""
Async Redis session manager for MCP Atlassian.

Handles session storage, retrieval, and expiry securely.

Attributes:
    redis_url (str): Redis connection URL.
    db (int): Redis database index.
    password (str | None): Redis password.
    _pool (aioredis.Redis | None): Redis connection pool.
"""
from typing import Any, Optional
import os
import json
import asyncio
import redis.asyncio as aioredis
import logging

logger = logging.getLogger(__name__)

class RedisManager:
    """Async Redis manager for session storage.

    Methods:
        connect(): Initialize Redis connection pool.
        close(): Close Redis connection pool.
        set_session(session_id, data, ttl): Store session data with TTL.
        get_session(session_id): Retrieve session data by ID.
        delete_session(session_id): Delete session by ID.
        session_exists(session_id): Check if session exists.
        refresh_session(session_id, ttl): Refresh session TTL.
    """
    def __init__(self, url: Optional[str] = None, db: int = 0, password: Optional[str] = None):
        """Initialize RedisManager.

        Args:
            url (str, optional): Redis connection URL. Defaults to env REDIS_URL or localhost.
            db (int): Redis database index. Defaults to 0.
            password (str, optional): Redis password. Defaults to env REDIS_PASSWORD or None.
        """
        self.redis_url = url or os.getenv("REDIS_URL", "redis://localhost:6379")
        self.db = db
        self.password = password or os.getenv("REDIS_PASSWORD")
        self._pool: aioredis.Redis | None = None

    async def connect(self):
        """Initialize Redis connection pool if not already connected. Raises on failure."""
        if not self._pool:
            try:
                self._pool = aioredis.from_url(
                    self.redis_url,
                    db=self.db,
                    password=self.password,
                    decode_responses=True,
                    encoding="utf-8",
                    max_connections=10,
                )
                # Test connection
                await self._pool.ping()
            except Exception as e:
                logger.error(f"Failed to connect to Redis at {self.redis_url}: {e}")
                raise

    async def health_check(self) -> bool:
        """Check if Redis is reachable and healthy.

        Returns:
            bool: True if Redis responds to PING, else False.
        """
        try:
            await self.connect()
            pong = await self._pool.ping()
            return pong is True or pong == "PONG"
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False

    async def close(self):
        """Close Redis connection pool."""
        if self._pool:
            try:
                await self._pool.close()
            except Exception as e:
                logger.warning(f"Error closing Redis connection: {e}")
            self._pool = None

    async def set_session(self, session_id: str, data: dict[str, Any], ttl: int = 3600):
        """Store session data with TTL.

        Args:
            session_id (str): Session key.
            data (dict): Session data.
            ttl (int): Time-to-live in seconds. Defaults to 3600.
        """
        await self.connect()
        value = json.dumps(data)
        await self._pool.set(session_id, value, ex=ttl)

    async def get_session(self, session_id: str) -> Optional[dict[str, Any]]:
        """Retrieve session data by ID.

        Args:
            session_id (str): Session key.

        Returns:
            dict or None: Session data if found, else None.
        """
        await self.connect()
        value = await self._pool.get(session_id)
        if value is None:
            return None
        try:
            return json.loads(value)
        except Exception:
            return None

    async def delete_session(self, session_id: str):
        """Delete session by ID.

        Args:
            session_id (str): Session key.
        """
        await self.connect()
        await self._pool.delete(session_id)

    async def session_exists(self, session_id: str) -> bool:
        """Check if session exists.

        Args:
            session_id (str): Session key.

        Returns:
            bool: True if session exists, else False.
        """
        await self.connect()
        return await self._pool.exists(session_id) == 1

    async def refresh_session(self, session_id: str, ttl: int = 3600):
        """Refresh session TTL.

        Args:
            session_id (str): Session key.
            ttl (int): New time-to-live in seconds. Defaults to 3600.
        """
        await self.connect()
        await self._pool.expire(session_id, ttl)

# Usage example (async):
# redis_mgr = RedisManager()
# await redis_mgr.set_session("session123", {"user_id": "abc", "creds": "..."})
# session = await redis_mgr.get_session("session123")
# await redis_mgr.delete_session("session123")
