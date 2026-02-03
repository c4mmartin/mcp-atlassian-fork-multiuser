"""Helpers for creating Jira/Confluence fetchers from session context."""

from __future__ import annotations

from starlette.requests import Request

from mcp_atlassian.confluence import ConfluenceFetcher
from mcp_atlassian.confluence.config import ConfluenceConfig
from mcp_atlassian.jira import JiraFetcher
from mcp_atlassian.jira.config import JiraConfig


def get_jira_fetcher_from_session(request: Request) -> JiraFetcher:
    session = getattr(request.state, "session", None)
    if not isinstance(session, dict):
        raise RuntimeError("No session found in request.state")

    url = session.get("jira_url")
    if not url:
        raise ValueError("Session is missing 'jira_url'")

    # Prefer explicit PAT fields.
    personal_token = session.get("jira_personal_token") or session.get("jira_token")
    username = session.get("jira_username") or session.get("jira_email")
    api_token = session.get("jira_api_token")

    if personal_token:
        config = JiraConfig(url=url, auth_type="pat", personal_token=personal_token)
    elif username and api_token:
        config = JiraConfig(
            url=url, auth_type="basic", username=username, api_token=api_token
        )
    else:
        raise ValueError(
            "Session does not contain Jira credentials. Provide either "
            "'jira_personal_token' (PAT) or ('jira_username' + 'jira_api_token')."
        )

    return JiraFetcher(config=config)


def get_confluence_fetcher_from_session(request: Request) -> ConfluenceFetcher:
    session = getattr(request.state, "session", None)
    if not isinstance(session, dict):
        raise RuntimeError("No session found in request.state")

    url = session.get("confluence_url")
    if not url:
        raise ValueError("Session is missing 'confluence_url'")

    personal_token = (
        session.get("confluence_personal_token") or session.get("confluence_token")
    )
    username = session.get("confluence_username") or session.get("confluence_email")
    api_token = session.get("confluence_api_token")

    if personal_token:
        config = ConfluenceConfig(
            url=url, auth_type="pat", personal_token=personal_token
        )
    elif username and api_token:
        config = ConfluenceConfig(
            url=url, auth_type="basic", username=username, api_token=api_token
        )
    else:
        raise ValueError(
            "Session does not contain Confluence credentials. Provide either "
            "'confluence_personal_token' (PAT) or ('confluence_username' + 'confluence_api_token')."
        )

    return ConfluenceFetcher(config=config)
