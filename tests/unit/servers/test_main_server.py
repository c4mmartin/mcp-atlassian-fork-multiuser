"""Tests for the main MCP server implementation."""

from contextlib import asynccontextmanager

from unittest.mock import AsyncMock, MagicMock, patch

import anyio
import httpx
import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_atlassian.servers.main import UserTokenMiddleware, main_mcp


@asynccontextmanager
async def lifespan_started(app):
    """Manually run ASGI lifespan for apps under httpx.ASGITransport.

    Our pinned httpx may not manage lifespan automatically.
    """
    to_app_send, to_app_receive = anyio.create_memory_object_stream(10)
    from_app_send, from_app_receive = anyio.create_memory_object_stream(10)

    async def _receive():
        return await to_app_receive.receive()

    async def _send(message):
        await from_app_send.send(message)

    scope = {"type": "lifespan", "asgi": {"version": "3.0"}}

    async with anyio.create_task_group() as tg:
        tg.start_soon(app, scope, _receive, _send)

        await to_app_send.send({"type": "lifespan.startup"})
        while True:
            message = await from_app_receive.receive()
            if message["type"] == "lifespan.startup.complete":
                break
            if message["type"] == "lifespan.startup.failed":
                raise RuntimeError(
                    f"Lifespan startup failed: {message.get('message', '')}"
                )

        try:
            yield
        finally:
            await to_app_send.send({"type": "lifespan.shutdown"})
            while True:
                message = await from_app_receive.receive()
                if message["type"] == "lifespan.shutdown.complete":
                    break
                if message["type"] == "lifespan.shutdown.failed":
                    raise RuntimeError(
                        f"Lifespan shutdown failed: {message.get('message', '')}"
                    )
            tg.cancel_scope.cancel()


@pytest.mark.anyio
async def test_run_server_stdio():
    """Test that main_mcp.run_async is called with stdio transport."""
    with patch.object(main_mcp, "run_async") as mock_run_async:
        mock_run_async.return_value = None
        await main_mcp.run_async(transport="stdio")
        mock_run_async.assert_called_once_with(transport="stdio")


@pytest.mark.anyio
async def test_run_server_sse():
    """Test that main_mcp.run_async is called with sse transport and correct port."""
    with patch.object(main_mcp, "run_async") as mock_run_async:
        mock_run_async.return_value = None
        test_port = 9000
        await main_mcp.run_async(transport="sse", port=test_port)
        mock_run_async.assert_called_once_with(transport="sse", port=test_port)


@pytest.mark.anyio
async def test_run_server_streamable_http():
    """Test that main_mcp.run_async is called with streamable-http transport and correct parameters."""
    with patch.object(main_mcp, "run_async") as mock_run_async:
        mock_run_async.return_value = None
        test_port = 9001
        test_host = "127.0.0.1"
        test_path = "/custom_mcp"
        await main_mcp.run_async(
            transport="streamable-http", port=test_port, host=test_host, path=test_path
        )
        mock_run_async.assert_called_once_with(
            transport="streamable-http", port=test_port, host=test_host, path=test_path
        )


@pytest.mark.anyio
async def test_run_server_invalid_transport():
    """Test that run_server raises ValueError for invalid transport."""
    # We don't need to patch run_async here as the error occurs before it's called
    with pytest.raises(ValueError) as excinfo:
        await main_mcp.run_async(transport="invalid")  # type: ignore

    assert "Unknown transport" in str(excinfo.value)
    assert "invalid" in str(excinfo.value)


@pytest.mark.anyio
async def test_health_check_endpoint():
    """Test the health check endpoint returns 200 and correct JSON response."""
    app = main_mcp.sse_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/healthz")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_sse_app_health_check_endpoint():
    """Test the /healthz endpoint on the SSE app returns 200 and correct JSON response."""
    app = main_mcp.sse_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_streamable_http_app_health_check_endpoint():
    """Test the /healthz endpoint on the Streamable HTTP app returns 200 and correct JSON response."""
    app = main_mcp.streamable_http_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_streamable_http_app_mcp_path_no_redirect():
    """Ensure /mcp accepts POST without a 307 redirect to /mcp/.

    Redirects are problematic for clients because auth headers may not be preserved.
    """
    app = main_mcp.streamable_http_app()
    async with lifespan_started(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test", follow_redirects=False
        ) as client:
            response = await client.post(
                "/mcp",
                headers={
                    "Content-Type": "application/json",
                    # Keep this test on the JSON response path.
                    # The SSE code path relies on asyncio loop primitives and can
                    # fail under the Trio anyio backend in unit tests.
                    "Accept": "application/json",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "pytest", "version": "0"},
                    },
                },
            )

            assert response.status_code != 307
            assert response.status_code != 405
            assert "location" not in response.headers


class TestUserTokenMiddleware:
    """Tests for the UserTokenMiddleware class."""

    @pytest.fixture
    def middleware(self):
        """Create a UserTokenMiddleware instance for testing."""
        mock_app = AsyncMock()
        # Create a mock MCP server to avoid warnings
        mock_mcp_server = MagicMock()
        mock_mcp_server.settings.streamable_http_path = "/mcp"
        return UserTokenMiddleware(mock_app, mcp_server_ref=mock_mcp_server)

    @pytest.fixture
    def mock_request(self):
        """Create a mock request for testing."""
        request = MagicMock(spec=Request)
        request.url.path = "/mcp"
        request.method = "POST"
        request.headers = {}
        # Create a real state object that can be modified
        from types import SimpleNamespace

        request.state = SimpleNamespace()
        return request

    @pytest.fixture
    def mock_call_next(self):
        """Create a mock call_next function."""
        mock_response = JSONResponse({"test": "response"})
        call_next = AsyncMock(return_value=mock_response)
        return call_next

    @pytest.mark.anyio
    async def test_cloud_id_header_extraction_success(
        self, middleware, mock_request, mock_call_next
    ):
        """Test successful cloud ID header extraction."""
        # Setup request with cloud ID header
        mock_request.headers = {
            "Authorization": "Bearer test-token",
            "X-Atlassian-Cloud-Id": "test-cloud-id-123",
        }

        result = await middleware.dispatch(mock_request, mock_call_next)

        # Verify cloud ID was extracted and stored in request state
        assert hasattr(mock_request.state, "user_atlassian_cloud_id")
        assert mock_request.state.user_atlassian_cloud_id == "test-cloud-id-123"

        # Verify the request was processed normally
        mock_call_next.assert_called_once_with(mock_request)
        assert result is not None
