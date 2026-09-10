"""Request-scoped bearer-token authentication for hosted MCP transport."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any


@dataclass
class RequestAuth:
    """Validated Copilot Studio token and its per-request Graph token."""

    access_token: str
    claims: dict[str, Any]
    graph_token: str | None = None


_request_auth: ContextVar[RequestAuth | None] = ContextVar("request_auth", default=None)


def set_request_auth(auth: RequestAuth | None):
    """Set authentication for the current async request."""
    return _request_auth.set(auth)


def reset_request_auth(token) -> None:
    """Restore the previous request authentication context."""
    _request_auth.reset(token)


def get_request_auth() -> RequestAuth | None:
    """Return the current request authentication context."""
    return _request_auth.get()