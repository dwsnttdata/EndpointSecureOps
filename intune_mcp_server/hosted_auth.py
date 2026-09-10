"""Validate Copilot Studio OAuth tokens and exchange them for Graph tokens."""

from __future__ import annotations

from typing import Any

import httpx
import jwt
from fastapi import Request
from fastapi.responses import JSONResponse
from jwt.algorithms import RSAAlgorithm

from .config import get_config
from .request_auth import RequestAuth, reset_request_auth, set_request_auth


class HostedAuthError(Exception):
    """Raised when the hosted MCP request is not authorized."""


async def _validate_token(token: str) -> dict[str, Any]:
    config = get_config()
    if not config.mcp_api_audience:
        raise HostedAuthError("MCP_API_AUDIENCE is not configured")

    unverified = jwt.decode(token, options={"verify_signature": False})
    issuer = unverified.get("iss", "")
    valid_issuers = {
        f"https://login.microsoftonline.com/{config.tenant_id}/v2.0",
        f"https://sts.windows.net/{config.tenant_id}/",
    }
    if issuer not in valid_issuers:
        raise HostedAuthError("Token issuer is not this tenant")

    header = jwt.get_unverified_header(token)
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(
            f"https://login.microsoftonline.com/{config.tenant_id}/discovery/v2.0/keys"
        )
        response.raise_for_status()
    key_data = next((key for key in response.json().get("keys", []) if key.get("kid") == header.get("kid")), None)
    if not key_data:
        raise HostedAuthError("Token signing key was not found")

    claims = jwt.decode(
        token,
        RSAAlgorithm.from_jwk(key_data),
        algorithms=["RS256"],
        audience=config.mcp_api_audience,
        issuer=issuer,
        options={"require": ["exp", "iat", "iss", "aud"]},
    )
    scopes = set((claims.get("scp") or "").split())
    if config.mcp_required_scope and config.mcp_required_scope not in scopes:
        raise HostedAuthError("Token does not contain the required MCP scope")
    return claims


async def hosted_auth_middleware(request: Request, call_next):
    """Authenticate only the hosted MCP endpoint and preserve request isolation."""
    config = get_config()
    if not config.mcp_auth_enabled or request.url.path.rstrip("/") != "/mcp":
        return await call_next(request)

    authorization = request.headers.get("authorization", "")
    if not authorization.lower().startswith("bearer "):
        return JSONResponse(
            {"error": "unauthorized", "message": "Bearer authentication is required."},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        token = authorization.split(" ", 1)[1].strip()
        claims = await _validate_token(token)
    except Exception as exc:
        return JSONResponse(
            {"error": "unauthorized", "message": str(exc)},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    context_token = set_request_auth(RequestAuth(access_token=token, claims=claims))
    try:
        return await call_next(request)
    finally:
        reset_request_auth(context_token)