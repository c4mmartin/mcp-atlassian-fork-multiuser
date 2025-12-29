"""
Helpers for creating Jira and Confluence clients from session context.
"""
from mcp_atlassian.jira.client import JiraClient
from mcp_atlassian.confluence.client import ConfluenceClient
from starlette.requests import Request


def get_jira_client(request: Request) -> JiraClient:
    """Create a JiraClient using credentials from request.state.session."""
    session = getattr(request.state, "session", None)
    if not session:
        raise RuntimeError("No session found in request.state")
    return JiraClient(
        url=session["jira_url"],
        api_token=session["jira_token"],
        email=session.get("jira_email"),
    )


def get_confluence_client(request: Request) -> ConfluenceClient:
    """Create a ConfluenceClient using credentials from request.state.session."""
    session = getattr(request.state, "session", None)
    if not session:
        raise RuntimeError("No session found in request.state")
    return ConfluenceClient(
        url=session["confluence_url"],
        api_token=session["confluence_token"],
        email=session.get("confluence_email"),
    )
