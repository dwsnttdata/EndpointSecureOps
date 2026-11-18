#!/usr/bin/env python3
"""
Intune & Entra MCP Server — Enterprise Edition (compact tool surface)

Architecture: 35 domain-grouped tools covering 280+ Graph endpoints.
Each tool accepts an `action` parameter so the LLM can invoke any operation
without the server needing to expose a separate MCP tool per endpoint.
No external CSV/JSON catalog files are required — everything is self-contained
in this module, which keeps the server portable for Copilot Studio hosting.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from intune_mcp_server import app_management as am
from intune_mcp_server import app_packaging as ap
from intune_mcp_server import app_sources as src
from intune_mcp_server import vendor_versions as vv
from intune_mcp_server.config import get_config  # noqa: F401  (ensures .env is loaded)
from intune_mcp_server.graph_client import AuthRequiredError, get_graph_client


def _transport_security() -> TransportSecuritySettings:
    """Allow local dev hosts plus the Azure App Service hostname (Copilot Studio hosting)."""
    allowed_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    allowed_origins = [
        "http://127.0.0.1:*",
        "http://localhost:*",
        "http://[::1]:*",
    ]

    azure_hostname = os.getenv("WEBSITE_HOSTNAME")
    if azure_hostname:
        allowed_hosts.append(azure_hostname)
        allowed_origins.extend(
            [
                f"https://{azure_hostname}",
                f"http://{azure_hostname}",
            ]
        )

    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


# Copilot Studio requires JSON responses (not SSE streaming) and a stateless
# HTTP transport since each call may be routed to a different instance.
mcp = FastMCP(
    "EndpointSecureOps-MCP",
    host="0.0.0.0",
    json_response=True,
    stateless_http=True,
    transport_security=_transport_security(),
)


def main() -> None:
    """Console entry point for stdio MCP transport."""
    mcp.run(transport="stdio")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _require_confirm(action: str, confirm: bool) -> dict[str, Any] | None:
    """Return an error dict if a destructive action is called without confirm=True."""
    if not confirm:
        return {
            "status": "confirmation_required",
            "message": f"Action '{action}' is destructive. Resend with confirm=True to proceed.",
        }
    return None


# ===========================================================================
# TOOL 1 — Connection & Health
# ===========================================================================
@mcp.tool()
async def authenticate_mcp_session() -> dict[str, Any]:
    """Authenticate the MCP session using the configured .env sign-in flow."""
    c = get_graph_client()
    try:
        auth_info = await c.ensure_authenticated()
        return {
            "status": "authenticated",
            "message": "MCP session is authenticated.",
            **auth_info,
        }
    except AuthRequiredError as exc:
        return {
            "status": "auth_required",
            "message": str(exc),
            "details": exc.details,
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


@mcp.tool()
async def test_connection() -> dict[str, Any]:
    """Test the connection to Microsoft Graph API and return tenant information."""
    try:
        c = get_graph_client()
        await c.ensure_authenticated()
        org = await c.get("/organization")
        info = org.get("value", [{}])[0]
        return {
            "status": "connected",
            "message": "Successfully connected to Microsoft Graph API",
            "tenant": {"displayName": info.get("displayName"), "id": info.get("id")},
        }
    except Exception as exc:
        if isinstance(exc, AuthRequiredError):
            return {
                "status": "auth_required",
                "message": str(exc),
                "details": exc.details,
            }
        return {"status": "error", "message": str(exc)}


@mcp.tool()
async def get_auth_status() -> dict[str, Any]:
    """Get current authentication mode and sign-in/cache status."""
    c = get_graph_client()
    status = await c.get_auth_status()
    if status.get("auth_mode") in {"delegated", "hybrid"} and status.get("require_user_login") and not status.get("cached_accounts"):
        try:
            await c.ensure_authenticated()
        except AuthRequiredError:
            pass
    return await c.get_auth_status()


@mcp.tool()
async def start_interactive_sign_in() -> dict[str, Any]:
    """Start user sign-in flow (device code) and return sign-in instructions."""
    c = get_graph_client()
    return await c.start_interactive_sign_in()


@mcp.tool()
async def complete_interactive_sign_in() -> dict[str, Any]:
    """Complete user sign-in flow after user enters device code."""
    c = get_graph_client()
    return await c.complete_interactive_sign_in()


@mcp.tool()
async def complete_interactive_login() -> dict[str, Any]:
    """Compatibility wrapper that completes the interactive sign-in flow for the MCP session."""
    return await complete_interactive_sign_in()


@mcp.tool()
async def connect_intune_mcp_server() -> dict[str, Any]:
    """One-step connection flow: trigger sign-in if needed, then verify Graph connectivity."""
    c = get_graph_client()

    # First, check whether an interactive sign-in is currently pending.
    status = await c.get_auth_status()
    if status.get("pending_interactive_login"):
        try:
            sign_in = await c.complete_interactive_sign_in()
            return {
                "status": "signed_in",
                "message": "Interactive sign-in completed. Re-run connect_intune_mcp_server to validate full connection.",
                "details": sign_in,
            }
        except Exception as exc:
            return {
                "status": "auth_pending",
                "message": "Complete the browser/device-code sign-in, then run connect_intune_mcp_server again.",
                "error": str(exc),
            }

    # Then attempt Graph connectivity. If user-login gate is enabled, this will
    # automatically trigger the configured sign-in flow from the .env settings.
    try:
        await c.ensure_authenticated()
        org = await c.get("/organization")
        info = org.get("value", [{}])[0]
        return {
            "status": "connected",
            "message": "Intune MCP server is connected and authenticated.",
            "tenant": {
                "displayName": info.get("displayName"),
                "id": info.get("id"),
            },
        }
    except Exception as exc:
        if isinstance(exc, AuthRequiredError):
            return {
                "status": "auth_required",
                "message": "User sign-in required. Complete the device-code flow and run connect_intune_mcp_server again.",
                "details": exc.details,
            }
        return {
            "status": "error",
            "message": str(exc),
        }


# ===========================================================================
# TOOL 2 — Intune Overview
# ===========================================================================
@mcp.tool()
async def get_intune_overview() -> dict[str, Any]:
    """Return device counts, compliance distribution and OS breakdown for the tenant."""
    c = get_graph_client()
    try:
        raw = await c.get("/deviceManagement/managedDevices?$select=complianceState,operatingSystem&$top=999")
        devices = raw.get("value", [])
        compliance: dict[str, int] = {}
        os_map: dict[str, int] = {}
        for d in devices:
            compliance[d.get("complianceState", "unknown")] = compliance.get(d.get("complianceState", "unknown"), 0) + 1
            os_map[d.get("operatingSystem", "unknown")] = os_map.get(d.get("operatingSystem", "unknown"), 0) + 1
        return {"total_devices": len(devices), "by_compliance": compliance, "by_os": os_map}
    except Exception as exc:
        return {"error": str(exc)}


# ===========================================================================
# TOOL 3 — Intune Managed Devices
# ===========================================================================
@mcp.tool()
async def manage_intune_devices(
    action: str,
    device_id: str = "",
    filter_query: str = "",
    search_term: str = "",
    search_by: str = "deviceName",
    top: int = 50,
    days_inactive: int = 30,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Intune managed devices. All device lifecycle and action operations.

    action values:
      list            — List all managed devices (supports filter_query, top)
      get             — Get full device details (requires device_id)
      search          — Search by deviceName/userPrincipalName/serialNumber (search_term, search_by)
      get_noncompliant— List non-compliant devices
      get_stale       — Devices inactive for N days (days_inactive)
      get_hardware    — Hardware inventory for a device (device_id)
      get_network     — Network info (MAC, subnet) for a device (device_id)
      get_installed_apps — Apps detected on a device (device_id)
      get_compliance_states — Compliance policy states for a device (device_id)
      get_log_requests — Diagnostic log collection requests for a device (device_id)
      sync            — Trigger sync on a device (device_id)
      bulk_sync       — Sync a list of devices (body: {device_ids: [...]})
      restart         — Restart a device remotely (device_id)
      lock            — Remote lock a device (device_id)
      rename          — Rename a device (device_id, body: {deviceName: "..."})
      locate          — Trigger GPS location on a device (device_id)
      reset_passcode  — Reset passcode on iOS/Android (device_id)
      bypass_activation_lock — Bypass iOS Activation Lock (device_id)
      enable_lost_mode   — Enable iOS Lost Mode (device_id, body: {message,phoneNumber,footer})
      disable_lost_mode  — Disable iOS Lost Mode (device_id)
      collect_diagnostics— Collect device diagnostics/logs (device_id)
      defender_scan   — Trigger Windows Defender scan (device_id, body: {quickScan: true/false})
      defender_update_signatures — Update Defender signatures (device_id)
      clean_device    — Clean Windows device; body: {keepUserData: bool} (device_id, confirm=True)
      delete          — Delete device from Intune (device_id, confirm=True)
      wipe            — Factory reset / wipe device (device_id, confirm=True)
      retire          — Retire device / remove company data (device_id, confirm=True)
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "list":
        ep = f"/deviceManagement/managedDevices?$top={min(top, 1000)}"
        if filter_query:
            ep += f"&$filter={filter_query}"
        r = await c.get(ep)
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "get":
        dev = await c.get(f"/deviceManagement/managedDevices/{device_id}")
        try:
            cs = await c.get(f"/deviceManagement/managedDevices/{device_id}/deviceCompliancePolicyStates")
            dev["_compliancePolicyStates"] = cs.get("value", [])
        except Exception:
            pass
        return dev

    if a == "search":
        ep = f"/deviceManagement/managedDevices?$filter=contains({search_by},'{search_term}')&$top={top}"
        r = await c.get(ep)
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "get_noncompliant":
        r = await c.get(f"/deviceManagement/managedDevices?$filter=complianceState eq 'noncompliant'&$top={top}")
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "get_stale":
        from datetime import datetime, timedelta, timezone
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days_inactive)).strftime("%Y-%m-%dT%H:%M:%SZ")
        r = await c.get(f"/deviceManagement/managedDevices?$filter=lastSyncDateTime le {cutoff}&$top={top}")
        return {"count": len(r.get("value", [])), "days_inactive": days_inactive, "devices": r.get("value", [])}

    if a == "get_hardware":
        return await c.get(f"/deviceManagement/managedDevices/{device_id}?$select=hardwareInformation,serialNumber,model,manufacturer", use_beta=True)

    if a == "get_network":
        return await c.get(f"/deviceManagement/managedDevices/{device_id}?$select=wifiMacAddress,ethernetMacAddress,deviceName")

    if a == "get_installed_apps":
        r = await c.get(f"/deviceManagement/managedDevices/{device_id}/detectedApps", use_beta=True)
        return {"count": len(r.get("value", [])), "apps": r.get("value", [])}

    if a == "get_compliance_states":
        r = await c.get(f"/deviceManagement/managedDevices/{device_id}/deviceCompliancePolicyStates")
        return {"count": len(r.get("value", [])), "states": r.get("value", [])}

    if a == "get_log_requests":
        r = await c.get(f"/deviceManagement/managedDevices/{device_id}/logCollectionRequests", use_beta=True)
        return {"count": len(r.get("value", [])), "requests": r.get("value", [])}

    if a == "sync":
        await c.post(f"/deviceManagement/managedDevices/{device_id}/syncDevice")
        return {"status": "success", "message": f"Sync triggered for {device_id}"}

    if a == "bulk_sync":
        ids = (body or {}).get("device_ids", [])
        results = []
        for did in ids:
            try:
                await c.post(f"/deviceManagement/managedDevices/{did}/syncDevice")
                results.append({"device_id": did, "status": "synced"})
            except Exception as exc:
                results.append({"device_id": did, "status": "error", "error": str(exc)})
        return {"results": results}

    if a == "restart":
        await c.post(f"/deviceManagement/managedDevices/{device_id}/rebootNow")
        return {"status": "success", "message": f"Restart triggered for {device_id}"}

    if a == "lock":
        await c.post(f"/deviceManagement/managedDevices/{device_id}/remoteLock")
        return {"status": "success", "message": f"Remote lock triggered for {device_id}"}

    if a == "rename":
        await c.post(f"/deviceManagement/managedDevices/{device_id}/setDeviceName", json=body or {}, use_beta=True)
        return {"status": "success"}

    if a == "locate":
        await c.post(f"/deviceManagement/managedDevices/{device_id}/locateDevice")
        return {"status": "success", "message": f"Locate triggered for {device_id}"}

    if a == "reset_passcode":
        await c.post(f"/deviceManagement/managedDevices/{device_id}/resetPasscode")
        return {"status": "success"}

    if a == "bypass_activation_lock":
        await c.post(f"/deviceManagement/managedDevices/{device_id}/bypassActivationLock")
        return {"status": "success"}

    if a == "enable_lost_mode":
        await c.post(f"/deviceManagement/managedDevices/{device_id}/enableLostMode", json=body or {}, use_beta=True)
        return {"status": "success"}

    if a == "disable_lost_mode":
        await c.post(f"/deviceManagement/managedDevices/{device_id}/disableLostMode", use_beta=True)
        return {"status": "success"}

    if a == "collect_diagnostics":
        default_body = {"templateType": {"@odata.type": "microsoft.graph.deviceLogCollectionRequest", "templateType": "predefined"}}
        await c.post(f"/deviceManagement/managedDevices/{device_id}/createDeviceLogCollectionRequest", json=body or default_body, use_beta=True)
        return {"status": "success"}

    if a == "defender_scan":
        await c.post(f"/deviceManagement/managedDevices/{device_id}/windowsDefenderScan", json=body or {"quickScan": False})
        return {"status": "success"}

    if a == "defender_update_signatures":
        await c.post(f"/deviceManagement/managedDevices/{device_id}/windowsDefenderUpdateSignatures")
        return {"status": "success"}

    if a in {"clean_device", "wipe", "retire", "delete"}:
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        if a == "clean_device":
            await c.post(f"/deviceManagement/managedDevices/{device_id}/cleanWindowsDevice", json=body or {})
        elif a == "wipe":
            await c.post(f"/deviceManagement/managedDevices/{device_id}/wipe", json=body or {"keepEnrollmentData": False, "keepUserData": False})
        elif a == "retire":
            await c.post(f"/deviceManagement/managedDevices/{device_id}/retire")
        elif a == "delete":
            await c.delete(f"/deviceManagement/managedDevices/{device_id}")
        return {"status": "success", "action": a, "device_id": device_id}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 4 — Device Encryption & BitLocker
# ===========================================================================
@mcp.tool()
async def manage_device_encryption(
    action: str,
    device_id: str = "",
    key_id: str = "",
) -> dict[str, Any]:
    """
    Manage device encryption keys and reports.

    action values:
      list_bitlocker_keys — List all BitLocker recovery keys for the tenant
      get_bitlocker_key   — Get a specific BitLocker recovery key with value (key_id)
      get_filevault_key   — Get macOS FileVault recovery key (device_id)
      get_encryption_report — Export device encryption status report
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "list_bitlocker_keys":
        r = await c.get("/informationProtection/bitlocker/recoveryKeys")
        return {"count": len(r.get("value", [])), "keys": r.get("value", [])}

    if a == "get_bitlocker_key":
        return await c.get(f"/informationProtection/bitlocker/recoveryKeys/{key_id}?$select=key")

    if a == "get_filevault_key":
        return await c.get(f"/deviceManagement/managedDevices/{device_id}/getFileVaultKey", use_beta=True)

    if a == "get_encryption_report":
        r = await c.post("/deviceManagement/reports/exportJobs", use_beta=True,
                         json={"reportName": "DeviceEncryption", "filter": "", "select": []})
        return r

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 5 — Intune App Management
# ===========================================================================
@mcp.tool()
async def manage_intune_apps(
    action: str,
    app_id: str = "",
    search_term: str = "",
    top: int = 50,
    body: dict | None = None,
    assignment_id: str = "",
    confirm: bool = False,
    group: str = "",
    intent: str = "required",
    mode: str = "add",
    notifications: str = "",
    app_type: str = "",
    target_app_id: str = "",
    relationship_type: str = "",
) -> dict[str, Any]:
    """
    Manage Intune mobile apps: search, install status, assignments, relationships, catalog updates.

    Easiest paths: assign_group (group by name, intent) and update_catalog_app (app_id). Both preview first
    and need one confirm=True. Read-only actions never ask.

    action values:
      list            — List apps with their real type (top, optional app_type e.g. win32CatalogApp)
      get             — Get app details + assignments (app_id)
      search          — Case-insensitive search by name or publisher (search_term)
      create          — Create/register a new app (body)
      update          — Update app metadata (app_id, body)
      delete          — Delete an app (app_id, confirm=True)
      get_assignments — Show who an app is assigned to, with group names (app_id)
      assign_group    — Assign to a group by name or id (app_id, group, intent=required|available|uninstall,
                        mode=add|replace, notifications for regular Win32 apps, confirm=True).
                        'All users' and 'All devices' are allowed only when named explicitly.
      assign          — Advanced: raw assignments (app_id, body: {assignments:[...]}, confirm=True)
      remove_assignment — Remove one assignment (app_id, assignment_id, confirm=True)
      get_install_status — Per-device install state and totals (app_id)
      get_relationships — Supersedence and dependencies (app_id)
      set_supersedence — Make app_id an update/replacement of target_app_id (relationship_type=update|replace, confirm=True)
      set_dependency  — Make app_id require target_app_id (relationship_type=autoInstall|detect, confirm=True)
      check_catalog_updates — Enterprise App Catalog apps with a newer catalog version, and retired entries
      update_catalog_app — Create the newest catalog version, link it as an update, copy assignments
                        (app_id, optional group to deploy to instead, confirm=True)
      list_discovered — List all apps discovered across managed devices
      check_vendor_versions — Compare detected Win32 apps with the vendor's published latest version
                        (optional search_term to narrow by name); apps with no official feed are listed as not checked
      get_mam_registrations — List managed app registrations (MAM enrollment)
    """
    c = get_graph_client()
    a = action.lower().strip()

    try:
        if a == "check_vendor_versions":
            detected = await ap._collect_pages(c, "/deviceManagement/detectedApps?$top=1000", max_pages=20)
            return await vv.check_vendor_versions(detected, search_term=search_term, index=WINGET_INDEX)

        if a == "list":
            return await am.list_apps(c, top, app_type)

        if a == "get":
            app = await c.get(f"/deviceAppManagement/mobileApps/{app_id}", use_beta=True)
            try:
                app["_assignments"] = await am.get_assignments(c, app_id)
            except Exception:
                pass
            return app

        if a == "search":
            return await am.search_apps(c, search_term, top)

        if a == "get_assignments":
            current = await am.get_assignments(c, app_id)
            return {"appId": app_id, "assignments": am.describe_assignments(current, await am.group_names(c, current)), "raw": current}

        if a == "assign_group":
            plan = await am.plan_assignment(c, app_id, group, intent, mode=mode, notifications=notifications)
            if not confirm:
                warnings = []
                if plan["broad"]:
                    warnings.append(f"This targets {plan['group']['displayName']}: every matching {'user' if 'Users' in plan['group']['displayName'] else 'device'} in the tenant.")
                if plan["removes"]:
                    warnings.append("These existing assignments would be removed: " + "; ".join(plan["removes"]))
                return {"status": "confirmation_required", "nothingChangedYet": True, "app": plan["app"]["displayName"], "before": plan["before"],
                        "after": plan["after"], "warnings": warnings, "next": "Call again with confirm=True to apply."}
            return await am.apply_assignments(c, app_id, plan["assignments"])

        if a == "get_relationships":
            return {"appId": app_id, "relationships": await am.get_relationships(c, app_id)}

        if a in ("set_supersedence", "set_dependency"):
            link = am.supersedence(target_app_id, relationship_type or "update") if a == "set_supersedence" else am.dependency(target_app_id, relationship_type or "autoInstall")
            if not confirm:
                return {"status": "confirmation_required", "nothingChangedYet": True, "relationship": link, "next": "Call again with confirm=True to apply."}
            return {"status": "success", "relationships": await am.set_relationships(c, app_id, [link])}

        if a == "check_catalog_updates":
            return await am.check_catalog_updates(c)

        if a == "update_catalog_app":
            plan = await am.plan_catalog_update(c, app_id, group)
            if plan["status"] == "up_to_date" or not confirm:
                return plan if plan["status"] == "up_to_date" else {"status": "confirmation_required", "nothingChangedYet": True, "updates": plan["old"]["displayName"],
                        "from": plan["old"]["displayVersion"], "to": plan["newPackage"]["version"], "willAssign": plan["assignmentSummary"],
                        "next": "Call again with confirm=True. The new app is created, linked as an update of the old one, then assigned."}
            created = await ap.create_catalog_app(c, plan["newPackage"]["id"], {})
            relationships = await am.set_relationships(c, created["id"], [am.supersedence(app_id, "update")])
            applied = await am.apply_assignments(c, created["id"], plan["assignments"]) if plan["assignments"] else {"assignments": []}
            return {"status": "updated", "newAppId": created["id"], "displayName": created.get("displayName"), "version": plan["newPackage"]["version"],
                    "supersedes": [item for item in relationships if item["targetId"] == app_id], "assignments": applied["assignments"]}
    except (am.AppManagementError, ap.PackagingError) as error:
        return {"error": str(error)}

    if a == "create":
        return await c.post("/deviceAppManagement/mobileApps", json=body or {})

    if a == "update":
        return await c.patch(f"/deviceAppManagement/mobileApps/{app_id}", json=body or {})

    if a == "delete":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/deviceAppManagement/mobileApps/{app_id}")
        return {"status": "success"}

    if a == "assign":
        b = body or {}
        if "mobileAppAssignments" not in b and "assignments" in b:
            b = {"mobileAppAssignments": b["assignments"]}
        if not confirm:
            names = await am.group_names(c, b.get("mobileAppAssignments", []))
            return {"status": "confirmation_required", "nothingChangedYet": True, "willReplaceAllAssignmentsWith": am.describe_assignments(b.get("mobileAppAssignments", []), names),
                    "currentAssignments": am.describe_assignments(await am.get_assignments(c, app_id), names),
                    "next": "Call again with confirm=True. This replaces every assignment; use assign_group to add one safely."}
        return await am.apply_assignments(c, app_id, b.get("mobileAppAssignments", []))

    if a == "remove_assignment":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/deviceAppManagement/mobileApps/{app_id}/assignments/{assignment_id}")
        return {"status": "success"}

    if a == "get_install_status":
        return await am.install_status(c, app_id)

    if a == "list_discovered":
        apps = await ap._collect_pages(c, f"/deviceManagement/detectedApps?$top={min(max(top, 1), 1000)}", max_pages=max(1, -(-top // 1000)))
        return {"count": len(apps[:top]), "apps": apps[:top]}

    if a == "get_mam_registrations":
        r = await c.get(f"/deviceAppManagement/managedAppRegistrations?$top={top}")
        return {"count": len(r.get("value", [])), "registrations": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 6 — App Config & MAM Policies
# ===========================================================================
@mcp.tool()
async def manage_app_config_mam(
    action: str,
    policy_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
    platform: str = "ios",
) -> dict[str, Any]:
    """
    Manage app configuration policies and MAM (app protection) policies.

    action values:
      list_config_policies   — List all managed app config policies (targeted)
      get_config_policy      — Get a specific app config policy (policy_id)
      create_config_policy   — Create an app config policy (body)
      update_config_policy   — Update an app config policy (policy_id, body)
      delete_config_policy   — Delete an app config policy (policy_id, confirm=True)
      list_protection_policies — List MAM/app protection policies
      create_protection_policy — Create an app protection policy (platform: ios|android, body)
      update_protection_policy — Update an app protection policy (policy_id, platform, body)
      delete_protection_policy — Delete an app protection policy (policy_id, platform, confirm=True)
    """
    c = get_graph_client()
    a = action.lower().strip()
    plat_ep = "/deviceAppManagement/iosManagedAppProtections" if platform.lower() == "ios" else "/deviceAppManagement/androidManagedAppProtections"

    if a == "list_config_policies":
        r = await c.get(f"/deviceAppManagement/targetedManagedAppConfigurations?$top={top}")
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    if a == "get_config_policy":
        return await c.get(f"/deviceAppManagement/targetedManagedAppConfigurations/{policy_id}")

    if a == "create_config_policy":
        return await c.post("/deviceAppManagement/targetedManagedAppConfigurations", json=body or {})

    if a == "update_config_policy":
        return await c.patch(f"/deviceAppManagement/targetedManagedAppConfigurations/{policy_id}", json=body or {})

    if a == "delete_config_policy":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/deviceAppManagement/targetedManagedAppConfigurations/{policy_id}")
        return {"status": "success"}

    if a == "list_protection_policies":
        r = await c.get(f"/deviceAppManagement/managedAppPolicies?$top={top}")
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    if a == "create_protection_policy":
        return await c.post(plat_ep, json=body or {})

    if a == "update_protection_policy":
        return await c.patch(f"{plat_ep}/{policy_id}", json=body or {})

    if a == "delete_protection_policy":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"{plat_ep}/{policy_id}")
        return {"status": "success"}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 7 — Compliance Policies
# ===========================================================================
@mcp.tool()
async def manage_compliance_policies(
    action: str,
    policy_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Intune device compliance policies — CRUD, assignment and status.

    action values:
      list        — List all compliance policies
      get         — Get compliance policy details (policy_id)
      create      — Create a new compliance policy (body)
      update      — Update a compliance policy (policy_id, body)
      delete      — Delete a compliance policy (policy_id, confirm=True)
      assign      — Assign policy to groups (policy_id, body: {assignments:[...]})
      get_status  — Get device deployment status for a policy (policy_id)
      list_assignments — List assignments for a policy (policy_id)
    """
    c = get_graph_client()
    a = action.lower().strip()
    base = "/deviceManagement/deviceCompliancePolicies"

    if a == "list":
        r = await c.get(f"{base}?$top={top}")
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    if a == "get":
        return await c.get(f"{base}/{policy_id}")

    if a == "create":
        return await c.post(base, json=body or {})

    if a == "update":
        return await c.patch(f"{base}/{policy_id}", json=body or {})

    if a == "delete":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"{base}/{policy_id}")
        return {"status": "success"}

    if a == "assign":
        return await c.post(f"{base}/{policy_id}/assign", json=body or {})

    if a == "get_status":
        r = await c.get(f"{base}/{policy_id}/deviceStatuses")
        return {"count": len(r.get("value", [])), "statuses": r.get("value", [])}

    if a == "list_assignments":
        r = await c.get(f"{base}/{policy_id}/assignments")
        return {"count": len(r.get("value", [])), "assignments": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 8 — Configuration Profiles
# ===========================================================================
@mcp.tool()
async def manage_configuration_profiles(
    action: str,
    profile_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Intune device configuration profiles — CRUD, assignment and status.

    action values:
      list        — List all configuration profiles
      get         — Get profile details (profile_id)
      create      — Create a new profile (body)
      update      — Update a profile (profile_id, body)
      delete      — Delete a profile (profile_id, confirm=True)
      assign      — Assign profile to groups (profile_id, body: {assignments:[...]})
      get_status  — Get device deployment status (profile_id)
      list_assignments — List assignments (profile_id)
    """
    c = get_graph_client()
    a = action.lower().strip()
    base = "/deviceManagement/deviceConfigurations"

    if a == "list":
        r = await c.get(f"{base}?$top={top}")
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    if a == "get":
        return await c.get(f"{base}/{profile_id}")

    if a == "create":
        return await c.post(base, json=body or {})

    if a == "update":
        return await c.patch(f"{base}/{profile_id}", json=body or {})

    if a == "delete":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"{base}/{profile_id}")
        return {"status": "success"}

    if a == "assign":
        return await c.post(f"{base}/{profile_id}/assign", json=body or {})

    if a == "get_status":
        r = await c.get(f"{base}/{profile_id}/deviceStatuses")
        return {"count": len(r.get("value", [])), "statuses": r.get("value", [])}

    if a == "list_assignments":
        r = await c.get(f"{base}/{profile_id}/assignments")
        return {"count": len(r.get("value", [])), "assignments": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 9 — Settings Catalog
# ===========================================================================
@mcp.tool()
async def manage_settings_catalog(
    action: str,
    policy_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Intune settings catalog configuration policies.

    action values:
      list    — List all settings catalog policies
      get     — Get policy details (policy_id)
      create  — Create a settings catalog policy (body)
      update  — Update a settings catalog policy (policy_id, body)
      delete  — Delete a policy (policy_id, confirm=True)
      assign  — Assign policy to groups (policy_id, body: {assignments:[...]})
    """
    c = get_graph_client()
    a = action.lower().strip()
    base = "/deviceManagement/configurationPolicies"

    if a == "list":
        r = await c.get(f"{base}?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    if a == "get":
        return await c.get(f"{base}/{policy_id}", use_beta=True)

    if a == "create":
        return await c.post(base, json=body or {}, use_beta=True)

    if a == "update":
        return await c.patch(f"{base}/{policy_id}", json=body or {}, use_beta=True)

    if a == "delete":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"{base}/{policy_id}", use_beta=True)
        return {"status": "success"}

    if a == "assign":
        return await c.post(f"{base}/{policy_id}/assign", json=body or {}, use_beta=True)

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 10 — ADMX / Group Policy Configurations
# ===========================================================================
@mcp.tool()
async def manage_admx_policies(
    action: str,
    config_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Intune ADMX (Administrative Templates / Group Policy) configurations.

    action values:
      list    — List all ADMX configurations
      get     — Get ADMX config details (config_id)
      create  — Create an ADMX configuration (body)
      delete  — Delete an ADMX configuration (config_id, confirm=True)
    """
    c = get_graph_client()
    a = action.lower().strip()
    base = "/deviceManagement/groupPolicyConfigurations"

    if a == "list":
        r = await c.get(f"{base}?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "configurations": r.get("value", [])}

    if a == "get":
        return await c.get(f"{base}/{config_id}", use_beta=True)

    if a == "create":
        return await c.post(base, json=body or {}, use_beta=True)

    if a == "delete":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"{base}/{config_id}", use_beta=True)
        return {"status": "success"}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 11 — Endpoint Security
# ===========================================================================
@mcp.tool()
async def manage_endpoint_security(
    action: str,
    policy_id: str = "",
    template_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Intune endpoint security policies (Antivirus, Firewall, EDR, etc.).

    action values:
      list_policies     — List all endpoint security policies
      get_policy        — Get policy details (policy_id)
      create_policy     — Create from a template (template_id, body)
      update_policy     — Update an endpoint security policy (policy_id, body)
      delete_policy     — Delete a policy (policy_id, confirm=True)
      assign_policy     — Assign to groups (policy_id, body: {assignments:[...]})
      get_policy_status — Device state summary for a policy (policy_id)
      list_templates    — List all security templates
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "list_policies":
        r = await c.get(f"/deviceManagement/intents?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    if a == "get_policy":
        return await c.get(f"/deviceManagement/intents/{policy_id}", use_beta=True)

    if a == "create_policy":
        return await c.post(f"/deviceManagement/templates/{template_id}/createInstance", use_beta=True, json=body or {})

    if a == "update_policy":
        return await c.patch(f"/deviceManagement/intents/{policy_id}", use_beta=True, json=body or {})

    if a == "delete_policy":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/deviceManagement/intents/{policy_id}", use_beta=True)
        return {"status": "success"}

    if a == "assign_policy":
        return await c.post(f"/deviceManagement/intents/{policy_id}/assign", use_beta=True, json=body or {})

    if a == "get_policy_status":
        return await c.get(f"/deviceManagement/intents/{policy_id}/deviceStateSummary", use_beta=True)

    if a == "list_templates":
        r = await c.get(f"/deviceManagement/templates?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "templates": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 12 — Security Baselines
# ===========================================================================
@mcp.tool()
async def manage_security_baselines(
    action: str,
    profile_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    View Intune security baseline templates and deployed profiles.

    action values:
      list_templates — List all security baseline templates
      list_profiles  — List deployed security baseline profiles
      get_status     — Get device deployment status for a profile (profile_id)
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "list_templates":
        r = await c.get(f"/deviceManagement/templates?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "templates": r.get("value", [])}

    if a == "list_profiles":
        r = await c.get(f"/deviceManagement/intents?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    if a == "get_status":
        r = await c.get(f"/deviceManagement/intents/{profile_id}/deviceStates", use_beta=True)
        return {"count": len(r.get("value", [])), "states": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 13 — Windows Update Policies
# ===========================================================================
@mcp.tool()
async def manage_windows_update(
    action: str,
    policy_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Windows Update rings and feature/quality/driver update profiles.

    action values:
      list_update_rings       — List all Windows update rings
      get_update_ring         — Get update ring details (policy_id)
      create_update_ring      — Create an update ring (body)
      update_update_ring      — Modify an update ring (policy_id, body)
      delete_update_ring      — Delete an update ring (policy_id, confirm=True)
      list_feature_updates    — List Windows feature update profiles
      get_feature_update      — Get a feature update profile (policy_id)
      create_feature_update   — Create a feature update profile (body)
      list_quality_updates    — List quality/expedite update policies
      list_driver_updates     — List driver update profiles
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "list_update_rings":
        r = await c.get(f"/deviceManagement/deviceConfigurations?$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&$top={top}")
        return {"count": len(r.get("value", [])), "rings": r.get("value", [])}

    if a == "get_update_ring":
        return await c.get(f"/deviceManagement/deviceConfigurations/{policy_id}")

    if a == "create_update_ring":
        return await c.post("/deviceManagement/deviceConfigurations", json=body or {})

    if a == "update_update_ring":
        return await c.patch(f"/deviceManagement/deviceConfigurations/{policy_id}", json=body or {})

    if a == "delete_update_ring":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/deviceManagement/deviceConfigurations/{policy_id}")
        return {"status": "success"}

    if a == "list_feature_updates":
        r = await c.get(f"/deviceManagement/windowsFeatureUpdateProfiles?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    if a == "get_feature_update":
        return await c.get(f"/deviceManagement/windowsFeatureUpdateProfiles/{policy_id}", use_beta=True)

    if a == "create_feature_update":
        return await c.post("/deviceManagement/windowsFeatureUpdateProfiles", use_beta=True, json=body or {})

    if a == "list_quality_updates":
        r = await c.get(f"/deviceManagement/windowsQualityUpdateProfiles?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    if a == "list_driver_updates":
        r = await c.get(f"/deviceManagement/windowsDriverUpdateProfiles?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 14 — Intune Scripts & Remediations
# ===========================================================================
@mcp.tool()
async def manage_intune_scripts(
    action: str,
    script_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
    script_type: str = "powershell",
    group_id: str = "",
    run_remediation_script: bool = False,
) -> dict[str, Any]:
    """
    Manage Intune PowerShell scripts, proactive remediations and macOS shell scripts.

    script_type: powershell | remediation | macos

    action values:
      list     — List scripts (script_type)
      get      — Get script details (script_id, script_type)
      create   — Upload a new script (body, script_type)
      update   — Update a script (script_id, body, script_type)
      delete   — Delete a script (script_id, script_type, confirm=True)
        assign   — Assign to an Entra security group (script_id, group_id, confirm=True);
                 body can be used for an advanced Graph assignment payload
      get_status — Device run states for a script (script_id, script_type)
    """
    c = get_graph_client()
    a = action.lower().strip()

    ep_map = {
        "powershell": "/deviceManagement/deviceManagementScripts",
        "remediation": "/deviceManagement/deviceHealthScripts",
        "macos":       "/deviceManagement/deviceShellScripts",
    }
    base = ep_map.get(script_type.lower(), ep_map["powershell"])

    if a == "list":
        r = await c.get(f"{base}?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "scripts": r.get("value", [])}

    if a == "get":
        return await c.get(f"{base}/{script_id}", use_beta=True)

    if a == "create":
        return await c.post(base, use_beta=True, json=body or {})

    if a == "update":
        return await c.patch(f"{base}/{script_id}", use_beta=True, json=body or {})

    if a == "delete":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"{base}/{script_id}", use_beta=True)
        return {"status": "success"}

    if a == "assign":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        if not script_id:
            return {"error": "script_id is required for assign."}
        if script_type.lower() not in ep_map:
            return {"error": "script_type must be powershell, remediation, or macos."}
        if group_id and body:
            return {"error": "Provide either group_id or body for assign, not both."}
        if group_id:
            if script_type.lower() == "remediation":
                assignment = {
                    "@odata.type": "#microsoft.graph.deviceHealthScriptAssignment",
                    "target": {
                        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                        "groupId": group_id,
                    },
                    "runRemediationScript": run_remediation_script,
                }
                assignment_body = {"deviceHealthScriptAssignments": [assignment]}
            else:
                assignment = {
                    "@odata.type": "#microsoft.graph.deviceManagementScriptGroupAssignment",
                    "targetGroupId": group_id,
                }
                assignment_body = {"deviceManagementScriptGroupAssignments": [assignment]}
        elif body:
            assignment_body = body
        else:
            return {"error": "Provide group_id or a Graph assignment body for assign."}
        return await c.post(f"{base}/{script_id}/assign", use_beta=True, json=assignment_body)

    if a == "get_status":
        r = await c.get(f"{base}/{script_id}/deviceRunStates", use_beta=True)
        return {"count": len(r.get("value", [])), "states": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 15 — Enrollment
# ===========================================================================
@mcp.tool()
async def manage_intune_enrollment(
    action: str,
    config_id: str = "",
    token_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Intune enrollment restrictions, Apple VPP/DEP tokens, and Android Enterprise.

    action values:
      list_restrictions      — List device enrollment configurations/restrictions
      create_restriction     — Create an enrollment restriction (body)
      update_restriction     — Update an enrollment restriction (config_id, body)
      delete_restriction     — Delete a restriction (config_id, confirm=True)
      assign_restriction     — Assign restriction to groups (config_id, body)
      list_vpp_tokens        — List Apple VPP tokens
      get_vpp_token          — Get a VPP token (token_id)
      sync_vpp_token         — Sync a VPP token (token_id)
      list_dep_tokens        — List Apple DEP/ADE onboarding settings
      sync_dep_token         — Sync a DEP/ADE token (token_id)
      list_android_enterprise — List Android Enterprise account settings
      get_failures_report    — Export enrollment failures report
      list_dep_profiles      — List enrollment profiles for a DEP token (token_id)
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "list_restrictions":
        r = await c.get(f"/deviceManagement/deviceEnrollmentConfigurations?$top={top}")
        return {"count": len(r.get("value", [])), "configurations": r.get("value", [])}

    if a == "create_restriction":
        return await c.post("/deviceManagement/deviceEnrollmentConfigurations", json=body or {})

    if a == "update_restriction":
        return await c.patch(f"/deviceManagement/deviceEnrollmentConfigurations/{config_id}", json=body or {})

    if a == "delete_restriction":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/deviceManagement/deviceEnrollmentConfigurations/{config_id}")
        return {"status": "success"}

    if a == "assign_restriction":
        return await c.post(f"/deviceManagement/deviceEnrollmentConfigurations/{config_id}/assign", json=body or {})

    if a == "list_vpp_tokens":
        r = await c.get(f"/deviceAppManagement/vppTokens?$top={top}")
        return {"count": len(r.get("value", [])), "tokens": r.get("value", [])}

    if a == "get_vpp_token":
        return await c.get(f"/deviceAppManagement/vppTokens/{token_id}")

    if a == "sync_vpp_token":
        return await c.post(f"/deviceAppManagement/vppTokens/{token_id}/syncLicenses")

    if a == "list_dep_tokens":
        r = await c.get(f"/deviceManagement/depOnboardingSettings?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "tokens": r.get("value", [])}

    if a == "sync_dep_token":
        return await c.post(f"/deviceManagement/depOnboardingSettings/{token_id}/syncWithAppleDeviceEnrollmentProgram", use_beta=True)

    if a == "list_android_enterprise":
        r = await c.get("/deviceManagement/androidManagedStoreAccountEnterpriseSettings", use_beta=True)
        return r

    if a == "get_failures_report":
        return await c.post("/deviceManagement/reports/exportJobs", use_beta=True,
                            json={"reportName": "DeviceEnrollmentFailures", "filter": "", "select": []})

    if a == "list_dep_profiles":
        r = await c.get(f"/deviceManagement/depOnboardingSettings/{token_id}/enrollmentProfiles", use_beta=True)
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 16 — Autopilot
# ===========================================================================
@mcp.tool()
async def manage_autopilot(
    action: str,
    device_id: str = "",
    profile_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Windows Autopilot devices and deployment profiles.

    action values:
      list_devices         — List all Autopilot device identities
      list_profiles        — List all Autopilot deployment profiles
      get_profile          — Get profile details (profile_id)
      create_profile       — Create an Autopilot deployment profile (body)
      update_profile       — Update a profile (profile_id, body)
      delete_profile       — Delete a profile (profile_id, confirm=True)
      assign_profile       — Assign profile to device/group (profile_id, body)
      import_device        — Import via hardware hash (body: {serialNumber,...})
      delete_device        — Delete Autopilot device registration (device_id, confirm=True)
      get_deployment_status — Autopilot deployment events
      list_esp_profiles    — List Enrollment Status Page profiles
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "list_devices":
        r = await c.get(f"/deviceManagement/windowsAutopilotDeviceIdentities?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "list_profiles":
        r = await c.get(f"/deviceManagement/windowsAutopilotDeploymentProfiles?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    if a == "get_profile":
        return await c.get(f"/deviceManagement/windowsAutopilotDeploymentProfiles/{profile_id}", use_beta=True)

    if a == "create_profile":
        return await c.post("/deviceManagement/windowsAutopilotDeploymentProfiles", use_beta=True, json=body or {})

    if a == "update_profile":
        return await c.patch(f"/deviceManagement/windowsAutopilotDeploymentProfiles/{profile_id}", use_beta=True, json=body or {})

    if a == "delete_profile":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/deviceManagement/windowsAutopilotDeploymentProfiles/{profile_id}", use_beta=True)
        return {"status": "success"}

    if a == "assign_profile":
        return await c.post(f"/deviceManagement/windowsAutopilotDeploymentProfiles/{profile_id}/assignments", use_beta=True, json=body or {})

    if a == "import_device":
        return await c.post("/deviceManagement/importedWindowsAutopilotDeviceIdentities", use_beta=True, json=body or {})

    if a == "delete_device":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/deviceManagement/windowsAutopilotDeviceIdentities/{device_id}", use_beta=True)
        return {"status": "success"}

    if a == "get_deployment_status":
        r = await c.get(f"/deviceManagement/autopilotEvents?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "events": r.get("value", [])}

    if a == "list_esp_profiles":
        r = await c.get(f"/deviceManagement/deviceEnrollmentConfigurations?$top={top}")
        profiles = [
            cfg for cfg in r.get("value", [])
            if cfg.get("@odata.type", "").endswith("windows10EnrollmentCompletionPageConfiguration")
        ]
        return {"count": len(profiles), "profiles": profiles}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 17 — Filters & Scope Tags
# ===========================================================================
@mcp.tool()
async def manage_filters_tags(
    action: str,
    filter_id: str = "",
    tag_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Intune assignment filters and scope tags.

    action values:
      list_filters   — List all assignment filters
      get_filter     — Get filter details (filter_id)
      create_filter  — Create an assignment filter (body)
      update_filter  — Update a filter (filter_id, body)
      delete_filter  — Delete a filter (filter_id, confirm=True)
      list_tags      — List all scope tags
      create_tag     — Create a scope tag (body)
      delete_tag     — Delete a scope tag (tag_id, confirm=True)
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "list_filters":
        r = await c.get(f"/deviceManagement/assignmentFilters?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "filters": r.get("value", [])}

    if a == "get_filter":
        return await c.get(f"/deviceManagement/assignmentFilters/{filter_id}", use_beta=True)

    if a == "create_filter":
        return await c.post("/deviceManagement/assignmentFilters", json=body or {}, use_beta=True)

    if a == "update_filter":
        return await c.patch(f"/deviceManagement/assignmentFilters/{filter_id}", json=body or {}, use_beta=True)

    if a == "delete_filter":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/deviceManagement/assignmentFilters/{filter_id}", use_beta=True)
        return {"status": "success"}

    if a == "list_tags":
        r = await c.get(f"/deviceManagement/roleScopeTags?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "tags": r.get("value", [])}

    if a == "create_tag":
        return await c.post("/deviceManagement/roleScopeTags", json=body or {}, use_beta=True)

    if a == "delete_tag":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/deviceManagement/roleScopeTags/{tag_id}", use_beta=True)
        return {"status": "success"}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 18 — Intune RBAC
# ===========================================================================
@mcp.tool()
async def manage_intune_rbac(
    action: str,
    role_id: str = "",
    assignment_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Intune RBAC role definitions and role assignments.

    action values:
      list_roles         — List all role definitions (built-in + custom)
      get_role           — Get role definition details (role_id)
      create_role        — Create a custom role (body)
      update_role        — Update a custom role (role_id, body)
      delete_role        — Delete a custom role (role_id, confirm=True)
      list_assignments   — List all role assignments
      create_assignment  — Assign role to user/group with scope (body)
      delete_assignment  — Remove a role assignment (assignment_id, confirm=True)
      list_resource_operations — List all available RBAC resource actions (permission strings)
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "list_resource_operations":
        r = await c.get("/deviceManagement/resourceOperations?$top=999")
        return {"count": len(r.get("value", [])), "operations": r.get("value", [])}

    if a == "list_roles":
        r = await c.get(f"/deviceManagement/roleDefinitions?$top={top}")
        return {"count": len(r.get("value", [])), "roles": r.get("value", [])}

    if a == "get_role":
        return await c.get(f"/deviceManagement/roleDefinitions/{role_id}")

    if a == "create_role":
        return await c.post("/deviceManagement/roleDefinitions", json=body or {})

    if a == "update_role":
        return await c.patch(f"/deviceManagement/roleDefinitions/{role_id}", json=body or {})

    if a == "delete_role":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/deviceManagement/roleDefinitions/{role_id}")
        return {"status": "success"}

    if a == "list_assignments":
        r = await c.get(f"/deviceManagement/roleAssignments?$top={top}")
        return {"count": len(r.get("value", [])), "assignments": r.get("value", [])}

    if a == "create_assignment":
        return await c.post("/deviceManagement/roleAssignments", json=body or {})

    if a == "delete_assignment":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/deviceManagement/roleAssignments/{assignment_id}")
        return {"status": "success"}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 19 — Windows 365 Cloud PC
# ===========================================================================
@mcp.tool()
async def manage_cloud_pc(
    action: str,
    cloud_pc_id: str = "",
    policy_id: str = "",
    connection_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Windows 365 Cloud PCs, provisioning policies and network connections.

    action values:
      list            — List all Cloud PCs
      get             — Get Cloud PC details (cloud_pc_id)
      get_overview    — Cloud PC overview/summary
      restart         — Restart a Cloud PC (cloud_pc_id)
      reprovision     — Reprovision a Cloud PC (cloud_pc_id, confirm=True)
      resize          — Resize/upgrade a Cloud PC (cloud_pc_id, body: {targetServicePlanId})
      restore         — Restore from snapshot (cloud_pc_id, body: {snapshotId})
      troubleshoot    — Trigger troubleshoot action (cloud_pc_id)
      list_snapshots  — List available snapshots (cloud_pc_id)
      get_audit_events — Audit event logs
      list_provisioning_policies — List provisioning policies
      create_provisioning_policy — Create a provisioning policy (body)
      assign_provisioning_policy — Assign policy to groups (policy_id, body)
      list_gallery_images   — List gallery images for provisioning
      list_connections      — List Azure network connections
    """
    c = get_graph_client()
    a = action.lower().strip()
    ve = "/deviceManagement/virtualEndpoint"

    if a == "list":
        r = await c.get(f"{ve}/cloudPCs?$top={top}")
        return {"count": len(r.get("value", [])), "cloudPCs": r.get("value", [])}

    if a == "get":
        return await c.get(f"{ve}/cloudPCs/{cloud_pc_id}")

    if a == "get_overview":
        r = await c.get(f"{ve}/cloudPCs?$top=999")
        items = r.get("value", [])
        status_map: dict[str, int] = {}
        for i in items:
            s = i.get("status", "unknown")
            status_map[s] = status_map.get(s, 0) + 1
        return {"total": len(items), "by_status": status_map}

    if a == "restart":
        await c.post(f"{ve}/cloudPCs/{cloud_pc_id}/reboot")
        return {"status": "success"}

    if a == "reprovision":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.post(f"{ve}/cloudPCs/{cloud_pc_id}/reprovision", json=body or {})
        return {"status": "success"}

    if a == "resize":
        return await c.post(f"{ve}/cloudPCs/{cloud_pc_id}/resize", use_beta=True, json=body or {})

    if a == "restore":
        await c.post(f"{ve}/cloudPCs/{cloud_pc_id}/restore", json=body or {})
        return {"status": "success"}

    if a == "troubleshoot":
        await c.post(f"{ve}/cloudPCs/{cloud_pc_id}/troubleshoot")
        return {"status": "success"}

    if a == "list_snapshots":
        r = await c.get(f"{ve}/cloudPCs/{cloud_pc_id}/snapshots", use_beta=True)
        return {"count": len(r.get("value", [])), "snapshots": r.get("value", [])}

    if a == "get_audit_events":
        r = await c.get(f"{ve}/auditEvents?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "events": r.get("value", [])}

    if a == "list_provisioning_policies":
        r = await c.get(f"{ve}/provisioningPolicies?$top={top}")
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    if a == "create_provisioning_policy":
        return await c.post(f"{ve}/provisioningPolicies", json=body or {})

    if a == "assign_provisioning_policy":
        return await c.post(f"{ve}/provisioningPolicies/{policy_id}/assign", json=body or {})

    if a == "list_gallery_images":
        r = await c.get(f"{ve}/galleryImages?$top={top}")
        return {"count": len(r.get("value", [])), "images": r.get("value", [])}

    if a == "list_connections":
        r = await c.get(f"{ve}/onPremisesConnections?$top={top}")
        return {"count": len(r.get("value", [])), "connections": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 20 — Entra ID Users
# ===========================================================================
@mcp.tool()
async def manage_entra_users(
    action: str,
    user_id: str = "",
    search_term: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Entra ID users — full lifecycle including licenses, manager, onboarding and offboarding.

    action values:
      list               — List all users (top)
      get                — Get user details (user_id or UPN)
      search             — Search users by displayName (search_term)
      create             — Create a new user (body)
      update             — Update user properties (user_id, body)
      delete             — Delete a user (user_id, confirm=True)
      enable             — Enable user account (user_id)
      disable            — Disable/block user sign-in (user_id)
      reset_password     — Reset user password (user_id, body: {newPassword, forceChangeAtNextSignIn})
      revoke_sessions    — Revoke all user refresh tokens (user_id)
      get_devices        — List managed devices for a user (user_id)
      get_licenses       — Get license assignments (user_id)
      assign_license     — Assign a license (user_id, body: {addLicenses:[{skuId}], removeLicenses:[]})
      remove_license     — Remove a license (user_id, body: {addLicenses:[], removeLicenses:[skuId]})
      list_available_licenses — List available license SKUs in tenant
      get_deleted_users  — List recently deleted users
      restore_user       — Restore a deleted user (user_id)
      assign_manager     — Set user's manager (user_id, body: {"@odata.id": managerUrl})
      remove_manager     — Remove user's manager (user_id)
      get_direct_reports — List user's direct reports (user_id)
      get_member_groups  — List groups the user belongs to (user_id)
      onboard_user       — Full onboard: create + manager + license + group membership (body)
      offboard_user      — Full offboard: disable + revoke sessions + remove groups (user_id, confirm=True)
      bulk_create        — Create multiple users from a list (body: {users: [...]})
      bulk_assign_license — Assign license to multiple users (body: {user_ids:[...], skuId:...})
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "list":
        r = await c.get(f"/users?$top={top}")
        return {"count": len(r.get("value", [])), "users": r.get("value", [])}

    if a == "get":
        return await c.get(f"/users/{user_id}")

    if a == "search":
        r = await c.get(f"/users?$filter=startswith(displayName,'{search_term}')&$top={top}")
        return {"count": len(r.get("value", [])), "users": r.get("value", [])}

    if a == "create":
        return await c.post("/users", json=body or {})

    if a == "update":
        await c.patch(f"/users/{user_id}", json=body or {})
        return {"status": "success"}

    if a == "delete":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/users/{user_id}")
        return {"status": "success"}

    if a == "enable":
        await c.patch(f"/users/{user_id}", json={"accountEnabled": True})
        return {"status": "success", "message": f"User {user_id} enabled"}

    if a == "disable":
        await c.patch(f"/users/{user_id}", json={"accountEnabled": False})
        return {"status": "success", "message": f"User {user_id} disabled"}

    if a == "reset_password":
        await c.patch(f"/users/{user_id}", json={"passwordProfile": body or {}})
        return {"status": "success"}

    if a == "revoke_sessions":
        return await c.post(f"/users/{user_id}/revokeSignInSessions")

    if a == "get_devices":
        r = await c.get(f"/users/{user_id}/managedDevices")
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "get_licenses":
        r = await c.get(f"/users/{user_id}/licenseDetails")
        return {"count": len(r.get("value", [])), "licenses": r.get("value", [])}

    if a in {"assign_license", "remove_license"}:
        return await c.post(f"/users/{user_id}/assignLicense", json=body or {})

    if a == "list_available_licenses":
        r = await c.get("/subscribedSkus")
        return {"count": len(r.get("value", [])), "skus": r.get("value", [])}

    if a == "get_deleted_users":
        r = await c.get(f"/directory/deletedItems/microsoft.graph.user?$top={top}")
        return {"count": len(r.get("value", [])), "users": r.get("value", [])}

    if a == "restore_user":
        return await c.post(f"/directory/deletedItems/{user_id}/restore")

    if a == "assign_manager":
        await c.put(f"/users/{user_id}/manager/$ref", json=body or {})
        return {"status": "success"}

    if a == "remove_manager":
        await c.delete(f"/users/{user_id}/manager/$ref")
        return {"status": "success"}

    if a == "get_direct_reports":
        r = await c.get(f"/users/{user_id}/directReports")
        return {"count": len(r.get("value", [])), "reports": r.get("value", [])}

    if a == "get_member_groups":
        r = await c.get(f"/users/{user_id}/memberOf")
        return {"count": len(r.get("value", [])), "groups": r.get("value", [])}

    if a == "onboard_user":
        data = body or {}
        user = await c.post("/users", json=data.get("user", {}))
        uid = user.get("id", "")
        results: list[dict] = [{"step": "create_user", "id": uid, "status": "ok"}]
        if data.get("manager"):
            try:
                await c.put(f"/users/{uid}/manager/$ref", json=data["manager"])
                results.append({"step": "assign_manager", "status": "ok"})
            except Exception as exc:
                results.append({"step": "assign_manager", "status": "error", "error": str(exc)})
        if data.get("license"):
            try:
                await c.post(f"/users/{uid}/assignLicense", json=data["license"])
                results.append({"step": "assign_license", "status": "ok"})
            except Exception as exc:
                results.append({"step": "assign_license", "status": "error", "error": str(exc)})
        for gid in data.get("group_ids", []):
            try:
                await c.post(f"/groups/{gid}/members/$ref", json={"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{uid}"})
                results.append({"step": f"add_to_group_{gid}", "status": "ok"})
            except Exception as exc:
                results.append({"step": f"add_to_group_{gid}", "status": "error", "error": str(exc)})
        return {"user_id": uid, "steps": results}

    if a == "offboard_user":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        results = []
        try:
            await c.patch(f"/users/{user_id}", json={"accountEnabled": False})
            results.append({"step": "disable_account", "status": "ok"})
        except Exception as exc:
            results.append({"step": "disable_account", "status": "error", "error": str(exc)})
        try:
            await c.post(f"/users/{user_id}/revokeSignInSessions")
            results.append({"step": "revoke_sessions", "status": "ok"})
        except Exception as exc:
            results.append({"step": "revoke_sessions", "status": "error", "error": str(exc)})
        return {"user_id": user_id, "steps": results}

    if a == "bulk_create":
        users = (body or {}).get("users", [])
        results = []
        for u in users:
            try:
                created = await c.post("/users", json=u)
                results.append({"upn": u.get("userPrincipalName"), "id": created.get("id"), "status": "ok"})
            except Exception as exc:
                results.append({"upn": u.get("userPrincipalName"), "status": "error", "error": str(exc)})
        return {"created": len([r for r in results if r.get("status") == "ok"]), "results": results}

    if a == "bulk_assign_license":
        data = body or {}
        sku = data.get("skuId", "")
        user_ids = data.get("user_ids", [])
        results = []
        for uid in user_ids:
            try:
                await c.post(f"/users/{uid}/assignLicense", json={"addLicenses": [{"skuId": sku}], "removeLicenses": []})
                results.append({"user_id": uid, "status": "ok"})
            except Exception as exc:
                results.append({"user_id": uid, "status": "error", "error": str(exc)})
        return {"results": results}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 21 — Entra ID Groups
# ===========================================================================
@mcp.tool()
async def manage_entra_groups(
    action: str,
    group_id: str = "",
    member_id: str = "",
    search_term: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Entra ID groups — full CRUD plus membership and ownership operations.

    action values:
      list            — List all groups
      get             — Get group details (group_id)
      search          — Search groups by displayName (search_term)
      create_security — Create a security group (body: {displayName, description})
      create_m365     — Create a Microsoft 365 group (body)
      create_dynamic  — Create a dynamic security group (body: includes membershipRule)
      update          — Update group properties (group_id, body)
      delete          — Delete a group (group_id, confirm=True)
      get_members     — List group members (group_id)
      add_member      — Add a member (group_id, member_id)
      remove_member   — Remove a member (group_id, member_id)
      get_owners      — List group owners (group_id)
      add_owner       — Add an owner (group_id, member_id)
      bulk_add_members — Add multiple members (group_id, body: {member_ids:[...]})
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "list":
        r = await c.get(f"/groups?$top={top}")
        return {"count": len(r.get("value", [])), "groups": r.get("value", [])}

    if a == "get":
        return await c.get(f"/groups/{group_id}")

    if a == "search":
        r = await c.get(f"/groups?$filter=startswith(displayName,'{search_term}')&$top={top}")
        return {"count": len(r.get("value", [])), "groups": r.get("value", [])}

    if a == "create_security":
        d = body or {}
        payload = {"displayName": d.get("displayName", ""), "description": d.get("description", ""),
                   "securityEnabled": True, "mailEnabled": False, "mailNickname": d.get("mailNickname", d.get("displayName", "group").replace(" ", ""))}
        return await c.post("/groups", json=payload)

    if a == "create_m365":
        d = body or {}
        payload = {"displayName": d.get("displayName", ""), "description": d.get("description", ""),
                   "groupTypes": ["Unified"], "securityEnabled": False, "mailEnabled": True,
                   "mailNickname": d.get("mailNickname", d.get("displayName", "group").replace(" ", ""))}
        payload.update({k: v for k, v in d.items() if k not in payload})
        return await c.post("/groups", json=payload)

    if a == "create_dynamic":
        return await c.post("/groups", json=body or {})

    if a == "update":
        await c.patch(f"/groups/{group_id}", json=body or {})
        return {"status": "success"}

    if a == "delete":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/groups/{group_id}")
        return {"status": "success"}

    if a == "get_members":
        r = await c.get(f"/groups/{group_id}/members?$top={top}")
        return {"count": len(r.get("value", [])), "members": r.get("value", [])}

    if a == "add_member":
        await c.post(f"/groups/{group_id}/members/$ref",
                     json={"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{member_id}"})
        return {"status": "success"}

    if a == "remove_member":
        await c.delete(f"/groups/{group_id}/members/{member_id}/$ref")
        return {"status": "success"}

    if a == "get_owners":
        r = await c.get(f"/groups/{group_id}/owners?$top={top}")
        return {"count": len(r.get("value", [])), "owners": r.get("value", [])}

    if a == "add_owner":
        await c.post(f"/groups/{group_id}/owners/$ref",
                     json={"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{member_id}"})
        return {"status": "success"}

    if a == "bulk_add_members":
        member_ids = (body or {}).get("member_ids", [])
        results = []
        for mid in member_ids:
            try:
                await c.post(f"/groups/{group_id}/members/$ref",
                             json={"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{mid}"})
                results.append({"member_id": mid, "status": "ok"})
            except Exception as exc:
                results.append({"member_id": mid, "status": "error", "error": str(exc)})
        return {"results": results}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 22 — Entra ID Devices
# ===========================================================================
@mcp.tool()
async def manage_entra_devices(
    action: str,
    device_id: str = "",
    intune_device_id: str = "",
    search_term: str = "",
    top: int = 50,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Entra ID device objects (separate from Intune managed devices).

    action values:
      list          — List all Entra ID devices
      get           — Get device details (device_id)
      search        — Search by displayName (search_term)
      enable        — Enable a device in Entra ID (device_id)
      disable       — Disable a device in Entra ID (device_id)
      delete_entra  — Delete device from Entra ID (device_id, confirm=True)
      delete_intune — Delete device from Intune (intune_device_id, confirm=True)
      delete_both   — Delete from both Intune and Entra (device_id + intune_device_id, confirm=True)
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "list":
        r = await c.get(f"/devices?$top={top}")
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "get":
        return await c.get(f"/devices/{device_id}")

    if a == "search":
        r = await c.get(f"/devices?$filter=startswith(displayName,'{search_term}')&$top={top}")
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "enable":
        await c.patch(f"/devices/{device_id}", json={"accountEnabled": True})
        return {"status": "success"}

    if a == "disable":
        await c.patch(f"/devices/{device_id}", json={"accountEnabled": False})
        return {"status": "success"}

    if a == "delete_entra":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/devices/{device_id}")
        return {"status": "success"}

    if a == "delete_intune":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/deviceManagement/managedDevices/{intune_device_id}")
        return {"status": "success"}

    if a == "delete_both":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        results = []
        for label, ep in [("intune", f"/deviceManagement/managedDevices/{intune_device_id}"), ("entra", f"/devices/{device_id}")]:
            try:
                await c.delete(ep)
                results.append({"source": label, "status": "deleted"})
            except Exception as exc:
                results.append({"source": label, "status": "error", "error": str(exc)})
        return {"results": results}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 23 — Conditional Access
# ===========================================================================
@mcp.tool()
async def manage_conditional_access(
    action: str,
    policy_id: str = "",
    location_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Entra ID Conditional Access policies and named locations.

    action values:
      list_policies    — List all CA policies
      get_policy       — Get CA policy details (policy_id)
      create_policy    — Create a new CA policy (body)
      update_policy    — Update a CA policy (policy_id, body)
      delete_policy    — Delete a CA policy (policy_id, confirm=True)
      enable_policy    — Enable a CA policy (policy_id)
      disable_policy   — Disable a CA policy (policy_id)
      list_locations   — List named locations
      create_location  — Create a named location (body)
      update_location  — Update a named location (location_id, body)
      delete_location  — Delete a named location (location_id, confirm=True)
    """
    c = get_graph_client()
    a = action.lower().strip()
    ca = "/identity/conditionalAccess/policies"
    nl = "/identity/conditionalAccess/namedLocations"

    if a == "list_policies":
        r = await c.get(f"{ca}?$top={top}")
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    if a == "get_policy":
        return await c.get(f"{ca}/{policy_id}")

    if a == "create_policy":
        return await c.post(ca, json=body or {})

    if a == "update_policy":
        await c.patch(f"{ca}/{policy_id}", json=body or {})
        return {"status": "success"}

    if a == "delete_policy":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"{ca}/{policy_id}")
        return {"status": "success"}

    if a == "enable_policy":
        await c.patch(f"{ca}/{policy_id}", json={"state": "enabled"})
        return {"status": "success"}

    if a == "disable_policy":
        await c.patch(f"{ca}/{policy_id}", json={"state": "disabled"})
        return {"status": "success"}

    if a == "list_locations":
        r = await c.get(f"{nl}?$top={top}")
        return {"count": len(r.get("value", [])), "locations": r.get("value", [])}

    if a == "create_location":
        return await c.post(nl, json=body or {})

    if a == "update_location":
        await c.patch(f"{nl}/{location_id}", json=body or {})
        return {"status": "success"}

    if a == "delete_location":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"{nl}/{location_id}")
        return {"status": "success"}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 24 — Identity Protection & Authentication
# ===========================================================================
@mcp.tool()
async def manage_identity_protection(
    action: str,
    user_id: str = "",
    method_id: str = "",
    top: int = 50,
    body: dict | None = None,
    filter_query: str = "",
) -> dict[str, Any]:
    """
    Manage identity protection, authentication methods, sign-in logs and risky users.

    action values:
      get_auth_methods         — List authentication methods for a user (user_id)
      get_mfa_status           — Check MFA registration status for a user (user_id)
      delete_auth_method       — Remove an authentication method (user_id, method_id, confirm=True)
      get_auth_methods_policy  — Get tenant-wide authentication methods policy
      get_sign_in_logs         — Sign-in logs (filter_query for OData filter, top)
      get_directory_audit_logs — Directory audit logs (filter_query, top)
      get_risky_users          — List risky users
      get_risk_detections      — Get risk detection events
      dismiss_risky_user       — Dismiss risk for a user (body: {userIds: [...]})
      confirm_compromised      — Confirm users as compromised (body: {userIds: [...]})
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "get_auth_methods":
        r = await c.get(f"/users/{user_id}/authentication/methods")
        return {"count": len(r.get("value", [])), "methods": r.get("value", [])}

    if a == "get_mfa_status":
        return await c.get(f"/reports/authenticationMethods/userRegistrationDetails/{user_id}", use_beta=True)

    if a == "delete_auth_method":
        await c.delete(f"/users/{user_id}/authentication/methods/{method_id}")
        return {"status": "success"}

    if a == "get_auth_methods_policy":
        return await c.get("/policies/authenticationMethodsPolicy")

    if a == "get_sign_in_logs":
        ep = f"/auditLogs/signIns?$top={top}"
        if filter_query:
            ep += f"&$filter={filter_query}"
        r = await c.get(ep)
        return {"count": len(r.get("value", [])), "logs": r.get("value", [])}

    if a == "get_directory_audit_logs":
        ep = f"/auditLogs/directoryAudits?$top={top}"
        if filter_query:
            ep += f"&$filter={filter_query}"
        r = await c.get(ep)
        return {"count": len(r.get("value", [])), "logs": r.get("value", [])}

    if a == "get_risky_users":
        r = await c.get(f"/identityProtection/riskyUsers?$top={top}")
        return {"count": len(r.get("value", [])), "users": r.get("value", [])}

    if a == "get_risk_detections":
        r = await c.get(f"/identityProtection/riskDetections?$top={top}")
        return {"count": len(r.get("value", [])), "detections": r.get("value", [])}

    if a == "dismiss_risky_user":
        return await c.post("/identityProtection/riskyUsers/dismiss", json=body or {})

    if a == "confirm_compromised":
        return await c.post("/identityProtection/riskyUsers/confirmCompromised", json=body or {})

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 25 — App Registrations & Enterprise Apps
# ===========================================================================
@mcp.tool()
async def manage_app_registrations(
    action: str,
    app_id: str = "",
    sp_id: str = "",
    search_term: str = "",
    top: int = 50,
    body: dict | None = None,
    days_until_expiry: int = 30,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Manage Entra ID app registrations and enterprise apps (service principals).

    action values:
      list_registrations   — List all app registrations
      get_registration     — Get app registration details (app_id)
      search_registrations — Search registrations by name (search_term)
      delete_registration  — Delete an app registration (app_id, confirm=True)
      get_expiring_credentials — App regs with credentials expiring soon (days_until_expiry)
      list_enterprise_apps — List all enterprise apps (service principals)
      get_enterprise_app   — Get enterprise app details (sp_id)
      search_enterprise_apps — Search enterprise apps by name (search_term)
      get_app_permissions  — Permissions granted to an enterprise app (sp_id)
      enable_enterprise_app  — Enable an enterprise app (sp_id)
      disable_enterprise_app — Disable an enterprise app (sp_id)
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "list_registrations":
        r = await c.get(f"/applications?$top={top}")
        return {"count": len(r.get("value", [])), "registrations": r.get("value", [])}

    if a == "get_registration":
        return await c.get(f"/applications/{app_id}")

    if a == "search_registrations":
        r = await c.get(f"/applications?$filter=startswith(displayName,'{search_term}')&$top={top}")
        return {"count": len(r.get("value", [])), "registrations": r.get("value", [])}

    if a == "delete_registration":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/applications/{app_id}")
        return {"status": "success"}

    if a == "get_expiring_credentials":
        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc) + timedelta(days=days_until_expiry)
        r = await c.get(f"/applications?$select=displayName,passwordCredentials,keyCredentials&$top=999")
        expiring = []
        for app in r.get("value", []):
            for cred in app.get("passwordCredentials", []) + app.get("keyCredentials", []):
                end = cred.get("endDateTime")
                if end and datetime.fromisoformat(end.replace("Z", "+00:00")) <= cutoff:
                    expiring.append({"app": app.get("displayName"), "credentialId": cred.get("keyId"), "expiresAt": end})
        return {"count": len(expiring), "expiring_credentials": expiring}

    if a == "list_enterprise_apps":
        r = await c.get(f"/servicePrincipals?$top={top}")
        return {"count": len(r.get("value", [])), "apps": r.get("value", [])}

    if a == "get_enterprise_app":
        return await c.get(f"/servicePrincipals/{sp_id}")

    if a == "search_enterprise_apps":
        r = await c.get(f"/servicePrincipals?$filter=startswith(displayName,'{search_term}')&$top={top}")
        return {"count": len(r.get("value", [])), "apps": r.get("value", [])}

    if a == "get_app_permissions":
        role_asgn = await c.get(f"/servicePrincipals/{sp_id}/appRoleAssignments")
        oauth2 = await c.get(f"/servicePrincipals/{sp_id}/oauth2PermissionGrants")
        return {"appRoleAssignments": role_asgn.get("value", []), "oauth2PermissionGrants": oauth2.get("value", [])}

    if a == "enable_enterprise_app":
        await c.patch(f"/servicePrincipals/{sp_id}", json={"accountEnabled": True})
        return {"status": "success"}

    if a == "disable_enterprise_app":
        await c.patch(f"/servicePrincipals/{sp_id}", json={"accountEnabled": False})
        return {"status": "success"}

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 26 — Tenant Administration
# ===========================================================================
@mcp.tool()
async def manage_tenant_admin(
    action: str,
    role_id: str = "",
    member_id: str = "",
    agreement_id: str = "",
    top: int = 50,
    body: dict | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """
    Tenant administration — org info, service health, directory roles, subscriptions, terms of use.

    action values:
      get_org_info          — Get organization/tenant information
      get_domains           — List tenant domains
      get_service_health    — M365 service health status overview
      get_service_issues    — Current/recent service issues
      get_message_center    — Message center posts/advisories
      get_planned_maintenance — Planned maintenance events
      list_directory_roles  — List active directory roles
      get_role_members      — List members of a directory role (role_id)
      get_global_admins     — List Global Administrator members
      assign_directory_role — Assign directory role to user/group (role_id, body)
      remove_directory_role_member — Remove member from role (role_id, member_id, confirm=True)
      get_subscriptions     — List subscribed license SKUs
      get_security_defaults — Check security defaults status
      list_terms_of_use     — List Terms of Use agreements
      create_terms_of_use   — Create a Terms of Use agreement (body)
      get_cross_tenant_policy — Get cross-tenant access (B2B) policy
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "get_org_info":
        r = await c.get("/organization")
        return r.get("value", [{}])[0]

    if a == "get_domains":
        r = await c.get("/domains")
        return {"count": len(r.get("value", [])), "domains": r.get("value", [])}

    if a == "get_service_health":
        r = await c.get("/admin/serviceAnnouncement/healthOverviews")
        return {"count": len(r.get("value", [])), "health": r.get("value", [])}

    if a == "get_service_issues":
        r = await c.get(f"/admin/serviceAnnouncement/issues?$top={top}")
        return {"count": len(r.get("value", [])), "issues": r.get("value", [])}

    if a == "get_message_center":
        r = await c.get(f"/admin/serviceAnnouncement/messages?$top={top}")
        return {"count": len(r.get("value", [])), "messages": r.get("value", [])}

    if a == "get_planned_maintenance":
        r = await c.get(f"/admin/serviceAnnouncement/messages?$filter=tags/any(t:t eq 'Action required')&$top={top}")
        return {"count": len(r.get("value", [])), "messages": r.get("value", [])}

    if a == "list_directory_roles":
        r = await c.get("/directoryRoles")
        return {"count": len(r.get("value", [])), "roles": r.get("value", [])}

    if a == "get_role_members":
        r = await c.get(f"/directoryRoles/{role_id}/members")
        return {"count": len(r.get("value", [])), "members": r.get("value", [])}

    if a == "get_global_admins":
        r = await c.get("/directoryRoles?$filter=roleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'")
        roles = r.get("value", [])
        if not roles:
            return {"members": []}
        members = await c.get(f"/directoryRoles/{roles[0]['id']}/members")
        return {"count": len(members.get("value", [])), "members": members.get("value", [])}

    if a == "assign_directory_role":
        await c.post(f"/directoryRoles/{role_id}/members/$ref", json=body or {})
        return {"status": "success"}

    if a == "remove_directory_role_member":
        guard = _require_confirm(a, confirm)
        if guard:
            return guard
        await c.delete(f"/directoryRoles/{role_id}/members/{member_id}/$ref")
        return {"status": "success"}

    if a == "get_subscriptions":
        r = await c.get("/subscribedSkus")
        return {"count": len(r.get("value", [])), "skus": r.get("value", [])}

    if a == "get_security_defaults":
        return await c.get("/policies/identitySecurityDefaultsEnforcementPolicy")

    if a == "list_terms_of_use":
        r = await c.get(f"/agreements?$top={top}")
        return {"count": len(r.get("value", [])), "agreements": r.get("value", [])}

    if a == "create_terms_of_use":
        return await c.post("/agreements", json=body or {})

    if a == "get_cross_tenant_policy":
        return await c.get("/policies/crossTenantAccessPolicy")

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 27 — Intune Reports & Analytics
# ===========================================================================
@mcp.tool()
async def manage_intune_reports(
    action: str,
    policy_id: str = "",
    app_id: str = "",
    device_id: str = "",
    top: int = 50,
    body: dict | None = None,
) -> dict[str, Any]:
    """
    Intune reports, endpoint analytics and export jobs.

    action values:
      compliance_report        — Device compliance summary
      config_profile_status    — Deployment status for a config profile (policy_id)
      compliance_policy_status — Deployment status for a compliance policy (policy_id)
      app_install_status       — App install summary (app_id)
      license_usage            — License usage summary
      hardware_inventory       — Hardware inventory export job
      malware_report           — Windows protection / malware state
      malware_on_device        — Detected malware on a device (device_id)
      device_protection_overview — Device protection status overview
      endpoint_analytics_score — Endpoint Analytics baseline scores
      startup_performance      — Device startup performance data
      app_reliability          — Application reliability/crash scores
      work_from_anywhere       — Work From Anywhere readiness report
      app_inventory            — App inventory across all devices
      certificate_report       — Device certificate status report
      co_management_report     — Co-management eligibility/status
      encryption_report        — Device encryption status export
      enrollment_failures      — Enrollment failures report
    """
    c = get_graph_client()
    a = action.lower().strip()

    if a == "compliance_report":
        r = await c.get("/deviceManagement/deviceCompliancePolicyDeviceStateSummary")
        return r

    if a == "config_profile_status":
        r = await c.get(f"/deviceManagement/deviceConfigurations/{policy_id}/deviceStatuses?$top={top}")
        return {"count": len(r.get("value", [])), "statuses": r.get("value", [])}

    if a == "compliance_policy_status":
        r = await c.get(f"/deviceManagement/deviceCompliancePolicies/{policy_id}/deviceStatuses?$top={top}")
        return {"count": len(r.get("value", [])), "statuses": r.get("value", [])}

    if a == "app_install_status":
        return await c.get(f"/deviceAppManagement/mobileApps/{app_id}/installSummary")

    if a == "license_usage":
        r = await c.get("/subscribedSkus")
        return {"count": len(r.get("value", [])), "skus": r.get("value", [])}

    if a == "hardware_inventory":
        return await c.post("/deviceManagement/reports/exportJobs", use_beta=True,
                            json={"reportName": "DevicesWithInventory", "filter": "", "select": []})

    if a == "malware_report":
        return await c.post("/deviceManagement/reports/exportJobs", use_beta=True,
                            json={"reportName": "Malware", "filter": "", "select": []})

    if a == "malware_on_device":
        r = await c.get(f"/deviceManagement/managedDevices/{device_id}/windowsProtectionState/detectedMalwareState", use_beta=True)
        return {"count": len(r.get("value", [])), "malware": r.get("value", [])}

    if a == "device_protection_overview":
        return await c.get("/deviceManagement/managedDeviceOverview")

    if a == "endpoint_analytics_score":
        r = await c.get(f"/deviceManagement/userExperienceAnalyticsBaselines?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "baselines": r.get("value", [])}

    if a == "startup_performance":
        r = await c.get(f"/deviceManagement/userExperienceAnalyticsDeviceStartupHistory?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "data": r.get("value", [])}

    if a == "app_reliability":
        r = await c.get(f"/deviceManagement/userExperienceAnalyticsAppHealthApplicationPerformance?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "data": r.get("value", [])}

    if a == "work_from_anywhere":
        return await c.post("/deviceManagement/reports/exportJobs", use_beta=True,
                            json={"reportName": "WorkFromAnywhereDeviceList", "filter": "", "select": []})

    if a == "app_inventory":
        return await c.post("/deviceManagement/reports/exportJobs", use_beta=True,
                            json={"reportName": "AppInvAggregate", "filter": "", "select": []})

    if a == "certificate_report":
        return await c.post("/deviceManagement/reports/exportJobs", use_beta=True,
                            json={"reportName": "AllDeviceCertificates", "filter": "", "select": []})

    if a == "co_management_report":
        r = await c.get(f"/deviceManagement/managedDevices?$select=id,deviceName,managementAgent,deviceEnrollmentType&$top={top}")
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "encryption_report":
        return await c.post("/deviceManagement/reports/exportJobs", use_beta=True,
                            json={"reportName": "DeviceEncryption", "filter": "", "select": []})

    if a == "enrollment_failures":
        return await c.post("/deviceManagement/reports/exportJobs", use_beta=True,
                            json={"reportName": "DeviceEnrollmentFailures", "filter": "", "select": []})

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 35 — App packaging, content upload and Enterprise App Catalog
# ===========================================================================
def _app_plan(summary: list[str], plan: dict[str, Any]) -> dict[str, Any]:
    return {"status": "confirmation_required", "nothingChangedYet": True, "summary": summary,
            "next": "Call again with the same inputs and confirm=True to create it. There are no further prompts after that.",
            "plan": plan}


WINGET_INDEX = src.WingetIndex()


def _new_download_dir() -> Path:
    roots = os.environ.get("APP_PACKAGING_ROOTS", "").strip()
    base = Path(roots.split(os.pathsep)[0]).expanduser() if roots else Path(tempfile.gettempdir())
    return base / "endpointsecureops-downloads" / uuid.uuid4().hex[:12]


def _merge_source_defaults(defaults: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    merged = dict(defaults)
    if "silentSwitches" in overrides:
        merged.pop("installCommandLine", None)
    if "detectPath" in overrides:
        merged.pop("rules", None)
    merged.update(overrides)
    return merged


async def _source_search(term: str, top: int) -> dict[str, Any]:
    top = max(1, min(int(top), 50))
    result: dict[str, Any] = {}
    try:
        result["catalog"] = (await ap.catalog_search(get_graph_client(), term, top=top))["packages"]
    except Exception as error:
        result["catalog"], result["catalogError"] = [], str(error)[:160]
    try:
        result["winget"] = await asyncio.to_thread(WINGET_INDEX.search, term, top)
    except src.SourceError as error:
        result["winget"], result["wingetError"] = [], str(error)
    try:
        result["store"] = await asyncio.to_thread(src.store_search, term, min(top, 10))
    except src.SourceError as error:
        result["store"], result["storeError"] = [], str(error)
    result["next"] = ("Catalog apps: add_app with catalog_package_id. Vendor packages: add_app with winget_id (the vendor's own installer, "
                      "checked against its published SHA-256 and signature). Microsoft Store apps: add_app with store_id.")
    return result


async def _acquire_installer(winget_id: str, version: str, architecture: str, url: str, overrides: dict[str, Any], folder: Path,
                             resolved: dict[str, Any] | None = None) -> dict[str, Any]:
    """Download from the vendor, verify the published hash, and refuse an invalid digital signature."""
    if winget_id:
        info = resolved or await asyncio.to_thread(src.resolve_winget, WINGET_INDEX, winget_id, version, architecture)
        target_url, name, sha = info["downloadUrl"], info["fileName"], info["sha256"]
    else:
        info, target_url, name, sha = {}, url, src.name_from_url(url), overrides.get("sha256")
    result = await asyncio.to_thread(src.download_installer, target_url, folder, name, sha)
    signature = await asyncio.to_thread(ap.verify_signature, Path(result["path"]))
    if signature["status"] != "Valid" and not overrides.get("allowUnsigned"):
        shutil.rmtree(folder, ignore_errors=True)
        raise ap.PackagingError(f"The installer's digital signature is not valid ({signature['status']}). Nothing was created. "
                                "If you trust this vendor file, repeat with body allowUnsigned=true.")
    return {**result, "signature": signature, "source": {"wingetId": info.get("wingetId"), "version": info.get("version"), "url": target_url}}


@mcp.tool()
async def manage_app_packaging(
    action: str,
    file_path: str = "",
    source_folder: str = "",
    setup_file: str = "",
    output_folder: str = "",
    search_term: str = "",
    catalog_package_id: str = "",
    body: dict | None = None,
    top: int = 25,
    overwrite: bool = False,
    confirm: bool = False,
    winget_id: str = "",
    version: str = "",
    architecture: str = "x64",
    download_url: str = "",
    store_id: str = "",
) -> dict[str, Any]:
    """
    Package, inspect and upload Windows apps; find any app from its vendor; add Enterprise App Catalog apps.

    Easiest path: add_app. Give it an app name (search_term), an installer (file_path: .msi, .exe, .msix, .appx
    or .intunewin), a folder (source_folder + setup_file), a winget_id, a Microsoft Store store_id, or a vendor
    download_url. For a name it looks in the Enterprise App Catalog first, then in the winget community index,
    which lists the vendor's own installer URL, SHA-256 hash, silent switches and product code for thousands of apps,
    and then the Microsoft Store.
    Downloads come from the vendor over HTTPS, are checked against the published SHA-256 and must carry a valid
    digital signature (body allowUnsigned=true overrides that, and is reported). It reads the installer, fills in name,
    publisher, version, commands and detection where it can, builds and encrypts the package, and asks only for
    what it cannot read. It previews first and needs one confirm=True to create anything; read-only and local
    actions never ask. body short-hands: silentSwitches (for example "/S"), detectPath (a file that exists once
    installed), displayName, publisher, description, installCommandLine, uninstallCommandLine, sha256 (download_url).

    Local file access is limited to APP_PACKAGING_ROOTS when set (required when hosted).

    action values:
      add_app           — Recommended: choose the right app type and create it
                          (search_term | winget_id | store_id | download_url | file_path | source_folder+setup_file)
      source_search     — Find an app in the Enterprise App Catalog, the winget community index and the Microsoft Store (search_term, top)
      source_get        — Vendor facts for one winget package, no download (winget_id, version, architecture)
      download_installer — Download and verify a vendor installer (winget_id or download_url, output_folder)
      inspect_installer — Read an .msi/.msix/.appx/.exe, its signature, and suggest install, uninstall and detection (file_path)
      build_intunewin   — Build a .intunewin locally (source_folder, setup_file, output_folder, overwrite)
      read_intunewin    — Read metadata of an existing .intunewin (file_path)
      create_win32_app  — Win32 app from a .intunewin, a single installer, or a folder (confirm=True)
      create_lob_app    — MSI or MSIX/APPX line-of-business app (file_path, body, confirm=True)
      catalog_search    — Search the Enterprise App Catalog (search_term, top)
      catalog_get       — Get one catalog package (catalog_package_id)
      create_catalog_app — Add a catalog app (catalog_package_id, body, confirm=True)
    """
    a = action.lower().strip()
    overrides = dict(body or {})
    download_dir: Path | None = None
    try:
        if a == "add_app" and store_id:
            if not store_id.isalnum() or len(store_id) != 12:
                return {"error": "store_id must be the 12-character Microsoft Store ID, for example 9NFTCH6J7FHV."}
            listing = next((item for item in await asyncio.to_thread(src.store_search, store_id.upper(), 5) if item["storeId"] == store_id.upper()), None)
            if listing is None:
                return {"error": f"No Microsoft Store app has the ID {store_id}. Use source_search to find it."}
            payload = ap.store_app_payload(store_id.upper(), overrides.pop("displayName", None) or listing["name"], overrides.pop("publisher", None) or listing["publisher"], dict(overrides))
            if not confirm and ap.require_confirmation():
                return _app_plan([f"Add Microsoft Store app '{payload['displayName']}' by {payload['publisher']} (Store ID {payload['packageIdentifier']})",
                                  f"Runs as {payload['installExperience']['runAsAccount']}",
                                  "Intune installs, updates and removes it from the Store; no installer, commands or detection rules are needed."], {"appPayload": payload})
            return await ap.create_store_app(get_graph_client(), payload)

        if a == "source_search":
            return await _source_search(search_term, top)

        if a == "source_get":
            return await asyncio.to_thread(src.resolve_winget, WINGET_INDEX, winget_id, version, architecture)

        if a == "download_installer":
            if not (winget_id or download_url):
                return {"error": "Give winget_id or download_url."}
            target = ap.resolve_path(output_folder, kind="dir", must_exist=False) if output_folder else _new_download_dir()
            return await _acquire_installer(winget_id, version, architecture, download_url, overrides, target)

        if a == "add_app":
            suffix = Path(file_path).suffix.lower()
            if winget_id or download_url:
                a = "create_win32_app"
            elif source_folder or suffix in (".intunewin", ".exe", ".msi"):
                a = "create_win32_app"
            elif suffix in ap.LOB_TYPES:
                a = "create_lob_app"
            elif search_term and not file_path:
                a = "catalog_add"
                if not catalog_package_id:
                    if not (await ap.catalog_search(get_graph_client(), search_term, top=10))["packages"]:
                        found = await asyncio.to_thread(WINGET_INDEX.search, search_term, 8)
                        exact = [item for item in found if src.normalize_name(item["name"]) == src.normalize_name(search_term)]
                        if len(found) == 1 or len(exact) == 1:
                            winget_id, a = (exact or found)[0]["id"], "create_win32_app"
                        elif found:
                            return {"status": "choose_one", "message": "Not in the Enterprise App Catalog. These vendor packages match; tell me which winget_id to use.", "matches": found}
                        else:
                            return {"error": f"'{search_term}' is not in the Enterprise App Catalog or the winget index. If you know the vendor's installer address, use download_url."}
            else:
                return {"error": "Give add_app an app name (search_term), a winget_id, a download_url, an installer (file_path), or a folder (source_folder and setup_file)."}

        if a == "create_win32_app" and (winget_id or download_url):
            resolved: dict[str, Any] = {}
            caller_rules = "rules" in overrides
            if winget_id:
                resolved = await asyncio.to_thread(src.resolve_winget, WINGET_INDEX, winget_id, version, architecture)
                overrides = _merge_source_defaults(resolved["defaults"], overrides)
            elif not download_url.lower().startswith("https://"):
                return {"error": "download_url must be an https:// address."}
            if not confirm and ap.require_confirmation():
                name = resolved.get("fileName") or Path(urlsplit(download_url).path).name or "installer.exe"
                preview = ap.win32_payload(None, name, Path(name).stem + ".intunewin", {key: value for key, value in overrides.items() if key not in ("allowUnsigned", "sha256")})
                missing = ap.missing_win32_fields(preview) if winget_id else []
                if missing:
                    return ap.needs_input(missing)
                origin = [f"Vendor download: {resolved.get('downloadHost') or urlsplit(download_url).hostname}",
                          "Verified against the vendor's published SHA-256, and the digital signature is checked" if resolved.get("sha256") else "No published SHA-256 was supplied; the digital signature is still checked",
                          "If the installer is not validly signed, creation stops unless you add allowUnsigned=true to body."]
                return _app_plan(ap.describe_win32(preview) + origin + resolved.get("notes", []), {"appPayload": preview, "source": {key: resolved.get(key) for key in ("wingetId", "version", "downloadUrl", "sha256")}})
            download_dir = _new_download_dir()
            fetched = await _acquire_installer(winget_id, version, architecture, download_url, overrides, download_dir, resolved)
            file_path, overrides = fetched["path"], {key: value for key, value in overrides.items() if key not in ("allowUnsigned", "sha256")}
            if resolved.get("installerType") == "msi" and not caller_rules:
                overrides.pop("rules", None)  # the downloaded MSI is inspected and gives a version-aware product-code rule

        if a == "inspect_installer":
            return await asyncio.to_thread(ap.inspect_installer, file_path)

        if a == "build_intunewin":
            return await asyncio.to_thread(ap.build_intunewin, source_folder, setup_file, output_folder, overwrite=overwrite)

        if a == "read_intunewin":
            return await asyncio.to_thread(ap.read_intunewin, file_path)

        if a == "create_win32_app":
            from_package = file_path.lower().endswith(".intunewin")
            folder = single = None
            if from_package:
                package = ap.resolve_path(file_path)
                meta = await asyncio.to_thread(ap.read_package, package)
                inspection, setup, package_name = None, meta["setupFile"], package.name
            else:
                if source_folder:
                    folder = ap.resolve_path(source_folder, kind="dir")
                    setup = setup_file.replace("\\", "/")
                    candidate = (folder / setup).resolve(strict=False)
                    if not setup.strip() or not (candidate == folder or folder in candidate.parents) or not candidate.is_file():
                        return {"error": "setup_file must be an existing file inside source_folder."}
                else:
                    single = candidate = ap.resolve_path(file_path)
                    setup = single.name
                inspect = candidate.suffix.lower() in (".msi", ".exe")
                inspection = await asyncio.to_thread(ap.inspect_installer, str(candidate)) if inspect else None
                package_name = Path(setup).stem + ".intunewin"
            payload = ap.win32_payload(inspection, setup, package_name, overrides)
            missing = ap.missing_win32_fields(payload)
            if missing:
                return ap.needs_input(missing, inspection["suggestions"] if inspection else None)
            if not confirm and ap.require_confirmation():
                return _app_plan(ap.describe_win32(payload), {"appPayload": payload})
            c = get_graph_client()
            with tempfile.TemporaryDirectory() as work_dir:
                if from_package:
                    package_path = package
                else:
                    build_from = ap.stage_single_file(single, Path(work_dir) / "stage") if single else folder
                    built = await asyncio.to_thread(ap.build_package, build_from, setup, Path(work_dir) / "out")
                    package_path = Path(built["packagePath"])
                    meta = await asyncio.to_thread(ap.read_package, package_path)
                info = ap.upload_info(meta)
                content = Path(work_dir) / ap.CONTENT_NAME
                await asyncio.to_thread(ap.extract_encrypted_content, package_path, content)
                await asyncio.to_thread(ap.verify_mac, content, info)
                return await ap.upload_app(c, "win32LobApp", payload, content, info)

        if a == "create_lob_app":
            file = ap.resolve_path(file_path)
            if file.suffix.lower() not in ap.LOB_TYPES:
                return {"error": "LOB apps support .msi, .msix, .appx, .msixbundle and .appxbundle. Use create_win32_app for EXE installers."}
            inspection = await asyncio.to_thread(ap.inspect_installer, str(file))
            type_name, payload = ap.lob_payload(inspection, overrides)
            required = ["displayName", "productCode", "productVersion"] if type_name == "windowsMobileMSI" else ["displayName", "identityName", "identityPublisherHash"]
            missing = [key for key in required if not payload.get(key)]
            if missing:
                return ap.needs_input(missing)
            if not confirm and ap.require_confirmation():
                return _app_plan(ap.describe_lob(type_name, payload), {"appPayload": payload, "appType": type_name})
            c = get_graph_client()
            with tempfile.TemporaryDirectory() as work_dir:
                encrypted = Path(work_dir) / "content.encrypted"
                info = await asyncio.to_thread(ap.encrypt_file, file, encrypted)
                return await ap.upload_app(c, type_name, payload, encrypted, info)

        if a == "catalog_search":
            return await ap.catalog_search(get_graph_client(), search_term, top=top)

        if a == "catalog_get":
            return await ap.catalog_get(get_graph_client(), catalog_package_id)

        if a == "catalog_add":
            c = get_graph_client()
            matches = (await ap.catalog_search(c, search_term, top=10))["packages"]
            if not matches:
                return {"error": f"No Enterprise App Catalog app matches '{search_term}'."}
            if len(matches) > 1 and not catalog_package_id:
                return {"status": "choose_one", "message": "Several catalog apps match. Tell me which one (its id), then I will continue.",
                        "matches": matches}
            catalog_package_id = catalog_package_id or matches[0]["id"]
            a = "create_catalog_app"

        if a == "create_catalog_app":
            c = get_graph_client()
            package = await ap.catalog_get(c, catalog_package_id)
            package.setdefault("id", catalog_package_id)
            converted = await ap.catalog_converted_app(c, catalog_package_id)
            payload = ap.catalog_app_payload(package, overrides, converted)
            if not confirm and ap.require_confirmation():
                app = payload["mobileApp"]
                lines = [f"Add Enterprise App Catalog app '{app.get('displayName')}' {app.get('displayVersion') or ''} by {app.get('publisher')}".replace("  ", " ")]
                if app.get("installCommandLine"):
                    lines.append(f"Install: {app['installCommandLine']}")
                return _app_plan(lines + ["Microsoft supplies the installer, commands and detection rules."], payload)
            return await ap.create_catalog_app(c, catalog_package_id, overrides)
    except (ap.PackagingError, src.SourceError) as error:
        return {"error": str(error)}
    finally:
        if download_dir:
            shutil.rmtree(download_dir, ignore_errors=True)

    return {"error": f"Unknown action: {action}"}


# ===========================================================================
# TOOL 28 — Discover Available Operations
# ===========================================================================
@mcp.tool()
async def discover_graph_operations(category: str = "") -> dict[str, Any]:
    """
    List all supported Graph operations grouped by tool/domain.
    Optionally filter by category name (e.g., 'devices', 'users', 'policies').

    Returns each tool with its name, description and all available action values.
    """
    catalog = {
        "manage_intune_devices": {
            "description": "Intune managed device lifecycle and device actions",
            "actions": ["list","get","search","get_noncompliant","get_stale","get_hardware","get_network",
                        "get_installed_apps","get_compliance_states","get_log_requests","sync","bulk_sync",
                        "restart","lock","rename","locate","reset_passcode","bypass_activation_lock",
                        "enable_lost_mode","disable_lost_mode","collect_diagnostics","defender_scan",
                        "defender_update_signatures","clean_device","delete","wipe","retire"],
        },
        "manage_device_encryption": {
            "description": "BitLocker recovery keys, FileVault and encryption reports",
            "actions": ["list_bitlocker_keys","get_bitlocker_key","get_filevault_key","get_encryption_report"],
        },
        "manage_intune_apps": {
            "description": "App search, install status, guarded assignments, relationships, catalog updates, vendor version checks",
            "actions": ["list","get","search","create","update","delete","get_assignments","assign_group","assign","remove_assignment",
                        "get_install_status","get_relationships","set_supersedence","set_dependency","check_catalog_updates",
                        "update_catalog_app","list_discovered","check_vendor_versions","get_mam_registrations"],
        },
        "manage_app_config_mam": {
            "description": "App configuration policies and MAM app protection policies",
            "actions": ["list_config_policies","get_config_policy","create_config_policy","update_config_policy",
                        "delete_config_policy","list_protection_policies","create_protection_policy",
                        "update_protection_policy","delete_protection_policy"],
        },
        "manage_compliance_policies": {
            "description": "Compliance policy CRUD, assignment and deployment status",
            "actions": ["list","get","create","update","delete","assign","get_status","list_assignments"],
        },
        "manage_configuration_profiles": {
            "description": "Configuration profile CRUD, assignment and deployment status",
            "actions": ["list","get","create","update","delete","assign","get_status","list_assignments"],
        },
        "manage_settings_catalog": {
            "description": "Settings catalog policy CRUD and assignment",
            "actions": ["list","get","create","update","delete","assign"],
        },
        "manage_admx_policies": {
            "description": "ADMX / Administrative Templates policy CRUD",
            "actions": ["list","get","create","delete"],
        },
        "manage_endpoint_security": {
            "description": "Endpoint security policies (AV, Firewall, EDR) and templates",
            "actions": ["list_policies","get_policy","create_policy","update_policy","delete_policy",
                        "assign_policy","get_policy_status","list_templates"],
        },
        "manage_security_baselines": {
            "description": "Security baseline templates and deployed profiles",
            "actions": ["list_templates","list_profiles","get_status"],
        },
        "manage_windows_update": {
            "description": "Windows update rings, feature/quality/driver update profiles",
            "actions": ["list_update_rings","get_update_ring","create_update_ring","update_update_ring",
                        "delete_update_ring","list_feature_updates","get_feature_update","create_feature_update",
                        "list_quality_updates","list_driver_updates"],
        },
        "manage_app_packaging": {
            "description": "Find any app from its vendor (catalog, winget index, Microsoft Store), verified download, Win32/LOB packaging and upload",
            "actions": ["add_app","source_search","source_get","download_installer","inspect_installer","build_intunewin","read_intunewin",
                        "create_win32_app","create_lob_app","catalog_search","catalog_get","create_catalog_app"],
        },
        "manage_intune_scripts": {
            "description": "PowerShell scripts, proactive remediations and macOS shell scripts",
            "actions": ["list","get","create","update","delete","assign","get_status"],
        },
        "manage_intune_enrollment": {
            "description": "Enrollment restrictions, Apple VPP/DEP tokens, Android Enterprise",
            "actions": ["list_restrictions","create_restriction","update_restriction","delete_restriction",
                        "assign_restriction","list_vpp_tokens","get_vpp_token","sync_vpp_token",
                        "list_dep_tokens","sync_dep_token","list_android_enterprise","get_failures_report",
                        "list_dep_profiles"],
        },
        "manage_autopilot": {
            "description": "Windows Autopilot devices, deployment profiles, ESP",
            "actions": ["list_devices","list_profiles","get_profile","create_profile","update_profile",
                        "delete_profile","assign_profile","import_device","delete_device",
                        "get_deployment_status","list_esp_profiles"],
        },
        "manage_filters_tags": {
            "description": "Assignment filters and scope tags",
            "actions": ["list_filters","get_filter","create_filter","update_filter","delete_filter",
                        "list_tags","create_tag","delete_tag"],
        },
        "manage_intune_rbac": {
            "description": "Intune RBAC role definitions and role assignments",
            "actions": ["list_roles","get_role","create_role","update_role","delete_role",
                        "list_assignments","create_assignment","delete_assignment"],
        },
        "manage_cloud_pc": {
            "description": "Windows 365 Cloud PC lifecycle, provisioning and connections",
            "actions": ["list","get","get_overview","restart","reprovision","resize","restore",
                        "troubleshoot","list_snapshots","get_audit_events","list_provisioning_policies",
                        "create_provisioning_policy","assign_provisioning_policy",
                        "list_gallery_images","list_connections"],
        },
        "manage_entra_users": {
            "description": "Entra ID user CRUD, licenses, manager, onboard/offboard, bulk ops",
            "actions": ["list","get","search","create","update","delete","enable","disable",
                        "reset_password","revoke_sessions","get_devices","get_licenses",
                        "assign_license","remove_license","list_available_licenses","get_deleted_users",
                        "restore_user","assign_manager","remove_manager","get_direct_reports",
                        "get_member_groups","onboard_user","offboard_user","bulk_create","bulk_assign_license"],
        },
        "manage_entra_groups": {
            "description": "Entra ID group CRUD, membership and ownership",
            "actions": ["list","get","search","create_security","create_m365","create_dynamic",
                        "update","delete","get_members","add_member","remove_member",
                        "get_owners","add_owner","bulk_add_members"],
        },
        "manage_entra_devices": {
            "description": "Entra ID device objects — enable, disable, delete",
            "actions": ["list","get","search","enable","disable","delete_entra","delete_intune","delete_both"],
        },
        "manage_conditional_access": {
            "description": "Conditional Access policies and named locations",
            "actions": ["list_policies","get_policy","create_policy","update_policy","delete_policy",
                        "enable_policy","disable_policy","list_locations","create_location",
                        "update_location","delete_location"],
        },
        "manage_identity_protection": {
            "description": "Auth methods, MFA status, sign-in logs, risky users, risk detections",
            "actions": ["get_auth_methods","get_mfa_status","delete_auth_method","get_auth_methods_policy",
                        "get_sign_in_logs","get_directory_audit_logs","get_risky_users",
                        "get_risk_detections","dismiss_risky_user","confirm_compromised"],
        },
        "manage_app_registrations": {
            "description": "App registrations and enterprise apps (service principals)",
            "actions": ["list_registrations","get_registration","search_registrations","delete_registration",
                        "get_expiring_credentials","list_enterprise_apps","get_enterprise_app",
                        "search_enterprise_apps","get_app_permissions","enable_enterprise_app",
                        "disable_enterprise_app"],
        },
        "manage_tenant_admin": {
            "description": "Tenant org info, service health, directory roles, subscriptions, terms of use",
            "actions": ["get_org_info","get_domains","get_service_health","get_service_issues",
                        "get_message_center","get_planned_maintenance","list_directory_roles",
                        "get_role_members","get_global_admins","assign_directory_role",
                        "remove_directory_role_member","get_subscriptions","get_security_defaults",
                        "list_terms_of_use","create_terms_of_use","get_cross_tenant_policy"],
        },
        "manage_intune_reports": {
            "description": "Compliance, configuration, app, encryption, analytics and export reports",
            "actions": ["compliance_report","config_profile_status","compliance_policy_status",
                        "app_install_status","license_usage","hardware_inventory","malware_report",
                        "malware_on_device","device_protection_overview","endpoint_analytics_score",
                        "startup_performance","app_reliability","work_from_anywhere","app_inventory",
                        "certificate_report","co_management_report","encryption_report","enrollment_failures"],
        },
    }

    if category:
        cat_lower = category.lower()
        catalog = {k: v for k, v in catalog.items() if cat_lower in k.lower() or cat_lower in v["description"].lower()}

    total_actions = sum(len(v["actions"]) for v in catalog.values())
    return {
        "tool_count": len(catalog) + 3,  # +3 for test_connection, get_intune_overview, discover_graph_operations
        "matching_tools": len(catalog),
        "total_actions_covered": total_actions,
        "tools": {name: {"description": info["description"], "action_count": len(info["actions"]), "actions": info["actions"]} for name, info in catalog.items()},
    }


if __name__ == "__main__":
    mcp.run()
