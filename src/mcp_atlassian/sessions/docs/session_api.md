# Session API Endpoints (Living Docs)

---

## TLS/HTTPS Enforcement (Multi-User Mode)

**TLS/HTTPS is REQUIRED for all multi-user deployments using HTTP transports.**

When running with `MCP_MULTIUSER=true` or `MCP_SESSIONS_ENABLED=true` and using HTTP transports (`sse` or `streamable-http`), the server will refuse to start unless TLS is enabled and certificate/key files are provided.

**Required environment variables:**

- `MCP_TLS_ENABLED=true`
- `MCP_TLS_CERT_FILE=/path/to/cert.pem`
- `MCP_TLS_KEY_FILE=/path/to/key.pem`
- `MCP_TLS_CA_FILE=/path/to/ca.pem` (optional)

If these are missing, the server will log an error and refuse to start in multi-user HTTP mode.

**Warning:**

- TLS/HTTPS is mandatory for production and multi-user deployments. Running without TLS is only allowed for local development or single-user mode, and will log a warning.

See `.env.example` for all TLS-related options.

## /session/login

- **Method:** POST
- **Description:** Create a new session by submitting Jira/Confluence credentials. Returns a session token for use in subsequent requests.
- **Request Body (JSON):**
  - `jira_url` (string, required for Jira)
  - `jira_token` (string, required for Jira)
  - `jira_email` (string, optional, for Jira Cloud)
  - `confluence_url` (string, required for Confluence)
  - `confluence_token` (string, required for Confluence)
  - `confluence_email` (string, optional, for Confluence Cloud)
- **Response (JSON):**
  - `session_token` (string)
- **Errors:**
  - 400: Invalid JSON
  - 401: Credential validation failed

## /session/logout

- **Method:** POST
- **Description:** Invalidate the current session by deleting it from Redis. Requires session token in Authorization header.
- **Headers:**
  - `Authorization: Bearer <session_token>`
- **Response (JSON):**
  - `message`: Session logged out and invalidated.
- **Errors:**
  - 401: Missing or invalid session token

---

## Notes

- No user accounts are created or managed—sessions are stateless and only store credentials for the session lifetime.
- Sessions mode is enabled with `MCP_SESSIONS_ENABLED=true`.
- In sessions mode, requests to `/mcp` must send the server-issued token in `Authorization: Bearer <session_token>`.
- `MCP_MULTIUSER=true` by itself enables user-token extraction (e.g., `Authorization: Token <PAT>`) but does not enforce session tokens.
- Credentials are validated at login and never stored globally.
- For HTTP transports (SSE/streamable-http), tool handlers should not rely on `ctx.request` always being present. If you need access to the Starlette `Request` (and `request.state.session`), use FastMCP's `fastmcp.server.dependencies.get_http_request()`.
- Sessions expire automatically after TTL or can be explicitly invalidated via logout.

---

_This document is updated as the session system evolves. Add new endpoints, behaviors, and security notes as needed._
