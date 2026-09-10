"""ASGI entrypoint for native MCP Streamable HTTP transport."""

from intune_mcp_server.server import mcp
from intune_mcp_server.hosted_auth import hosted_auth_middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route


async def health(request):
	return JSONResponse({"status": "ok", "service": "EndpointOps-MCP"})


# Exposes native MCP over Streamable HTTP at /mcp.
app = mcp.streamable_http_app()
app.routes.insert(0, Route("/health", health, methods=["GET"]))
app.add_middleware(BaseHTTPMiddleware, dispatch=hosted_auth_middleware)