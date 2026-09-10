"""Configuration management for Microsoft Graph MCP Server."""

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from the server-local .env file
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


@dataclass
class GraphConfig:
    """Microsoft Graph API configuration."""
    
    tenant_id: str
    client_id: str
    client_secret: str
    auth_mode: str = "app"
    require_user_login: bool = False
    interactive_login_mode: str = "device_code"
    user_auth_scopes: list[str] | None = None
    token_cache_path: str = str(PROJECT_ROOT / ".msal_token_cache.bin")
    graph_endpoint: str = "https://graph.microsoft.com/v1.0"
    beta_endpoint: str = "https://graph.microsoft.com/beta"
    mcp_auth_enabled: bool = False
    mcp_api_audience: str = ""
    mcp_required_scope: str = "Mcp.Access"
    mcp_client_secret: str = ""
    
    @classmethod
    def from_env(cls) -> "GraphConfig":
        """Load configuration from environment variables."""
        def _parse_bool(value: str | None, default: bool = False) -> bool:
            if value is None:
                return default
            return value.strip().lower() in {"1", "true", "yes", "y", "on"}

        auth_mode = (os.getenv("AUTH_MODE", "app") or "app").strip().lower()
        if auth_mode not in {"app", "delegated", "hybrid"}:
            raise ValueError("Invalid AUTH_MODE. Use one of: app, delegated, hybrid")

        require_user_login = _parse_bool(os.getenv("REQUIRE_USER_LOGIN"), default=False)
        interactive_login_mode = (os.getenv("INTERACTIVE_LOGIN_MODE", "device_code") or "device_code").strip().lower()
        if interactive_login_mode not in {"device_code", "browser"}:
            raise ValueError("Invalid INTERACTIVE_LOGIN_MODE. Use one of: device_code, browser")
        scopes_raw = os.getenv("USER_AUTH_SCOPES", "User.Read")
        user_auth_scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()]

        tenant_id = os.getenv("TENANT_ID")
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
        mcp_auth_enabled = _parse_bool(os.getenv("MCP_AUTH_ENABLED"), default=False)
        mcp_api_audience = (os.getenv("MCP_API_AUDIENCE", "") or "").strip()
        mcp_required_scope = (os.getenv("MCP_REQUIRED_SCOPE", "Mcp.Access") or "Mcp.Access").strip()
        mcp_client_secret = os.getenv("MCP_CLIENT_SECRET", client_secret or "") or ""

        if auth_mode in {"app", "hybrid"} and not all([tenant_id, client_id, client_secret]):
            raise ValueError(
                "Missing required environment variables. "
                "Please set TENANT_ID, CLIENT_ID, and CLIENT_SECRET in your .env file."
            )
        if auth_mode == "delegated" and not all([tenant_id, client_id]):
            raise ValueError(
                "Missing required environment variables for delegated auth. "
                "Please set TENANT_ID and CLIENT_ID in your .env file."
            )
        if mcp_auth_enabled:
            if auth_mode != "delegated":
                raise ValueError("MCP_AUTH_ENABLED requires AUTH_MODE=delegated")
            if not mcp_api_audience or not mcp_client_secret:
                raise ValueError(
                    "Hosted delegated auth requires MCP_API_AUDIENCE and MCP_CLIENT_SECRET."
                )
        
        return cls(
            tenant_id=tenant_id or "",
            client_id=client_id or "",
            client_secret=client_secret or "",
            auth_mode=auth_mode,
            require_user_login=require_user_login,
            interactive_login_mode=interactive_login_mode,
            user_auth_scopes=user_auth_scopes,
            token_cache_path=os.getenv("TOKEN_CACHE_PATH", str(PROJECT_ROOT / ".msal_token_cache.bin")),
            graph_endpoint=os.getenv("GRAPH_ENDPOINT", "https://graph.microsoft.com/v1.0"),
            beta_endpoint=os.getenv("BETA_ENDPOINT", "https://graph.microsoft.com/beta"),
            mcp_auth_enabled=mcp_auth_enabled,
            mcp_api_audience=mcp_api_audience,
            mcp_required_scope=mcp_required_scope,
            mcp_client_secret=mcp_client_secret,
        )


# Global config instance (lazy loaded)
_config: GraphConfig | None = None


def get_config() -> GraphConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = GraphConfig.from_env()
    return _config

