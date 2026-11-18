"""Intune app management: search, install status, assignments, relationships and catalog updates."""
from __future__ import annotations

import asyncio
import csv
import io
import re
import zipfile
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from intune_mcp_server import app_packaging as ap

APPS = "/deviceAppManagement/mobileApps"
GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
INTENTS = ("required", "available", "uninstall", "availableWithoutEnrollment")
NOTIFICATIONS = ("showAll", "showReboot", "hideAll")
BROAD_TARGETS = {"all users": "#microsoft.graph.allLicensedUsersAssignmentTarget", "all devices": "#microsoft.graph.allDevicesAssignmentTarget"}
CATALOG_TYPE = "#microsoft.graph.win32CatalogApp"
WIN32_TYPE = "#microsoft.graph.win32LobApp"


class AppManagementError(ValueError):
    """Operator-facing failure; never contains credentials."""


def _guid(value: str, what: str = "app_id") -> str:
    if not GUID.match(value or ""):
        raise AppManagementError(f"{what} must be a GUID.")
    return value.lower()


def _version_key(version: str | None) -> list[int]:
    return [int(part) if part.isdigit() else 0 for part in re.split(r"[.\-_+ ]", version or "") if part]


def _odata_string(value: str) -> str:
    return value.replace("'", "''")


def app_summary(app: dict[str, Any]) -> dict[str, Any]:
    kind = str(app.get("@odata.type") or "").rsplit(".", 1)[-1]
    return {"id": app.get("id"), "displayName": app.get("displayName"), "displayVersion": app.get("displayVersion"), "publisher": app.get("publisher"),
            "type": kind or None, "publishingState": app.get("publishingState"), "isAssigned": app.get("isAssigned"),
            "createdDateTime": app.get("createdDateTime")}


# ------------------------------------------------------------------------ list / search
async def list_apps(client: Any, top: int = 100, app_type: str = "") -> dict[str, Any]:
    """Beta endpoint, so catalog apps keep their real type instead of showing as plain Win32 apps."""
    top = max(1, min(int(top), 1000))
    query = f"{APPS}?$top={min(top, 100)}"
    if app_type:
        if not re.fullmatch(r"[A-Za-z0-9]+", app_type):
            raise AppManagementError("app_type must be a type name such as win32CatalogApp or win32LobApp.")
        query += "&$filter=" + quote(f"isof('microsoft.graph.{app_type}')", safe="(),=.'")
    apps = await ap._collect_pages(client, query, max_pages=max(1, -(-top // 100)))
    return {"count": len(apps[:top]), "apps": [app_summary(app) for app in apps[:top]]}


async def search_apps(client: Any, term: str, top: int = 50) -> dict[str, Any]:
    """Case-insensitive name/publisher match.

    $count with ConsistencyLevel makes this endpoint return no rows and contains() is case-sensitive,
    so $search narrows the set and the match is repeated locally; a full scan is the fallback.
    """
    needle = (term or "").replace('"', " ").strip()
    if not needle:
        raise AppManagementError("search_term is required.")
    found: dict[str, dict[str, Any]] = {}
    word = ap.search_word(needle)
    try:
        if word:
            for app in await ap._collect_pages(client, f"{APPS}?$search={quote(chr(34) + word + chr(34), safe='')}&$top=100", max_pages=3):
                found[app["id"]] = app
    except Exception:
        found = {}
    if not found:
        for app in await ap._collect_pages(client, f"{APPS}?$top=100", max_pages=20):
            found[app["id"]] = app
    lowered = needle.casefold()
    matches = [app for app in found.values() if lowered in str(app.get("displayName") or "").casefold() or lowered in str(app.get("publisher") or "").casefold()]
    matches.sort(key=lambda app: (not str(app.get("displayName") or "").casefold().startswith(lowered), str(app.get("displayName") or "").casefold()))
    return {"count": len(matches[:top]), "apps": [app_summary(app) for app in matches[:top]]}


# ------------------------------------------------------------------------ install status
def _validate_export_url(url: str) -> None:
    parts = urlsplit(url or "")
    if parts.scheme != "https" or not (parts.hostname or "").lower().endswith(ap.BLOB_HOST_SUFFIXES):
        raise AppManagementError("The report download address was not an Azure Blob Storage HTTPS address.")


async def install_overview(client: Any, app_id: str) -> dict[str, Any]:
    app_id = _guid(app_id)
    report = await client.post("/deviceManagement/reports/getAppStatusOverviewReport", use_beta=True,
                               json={"filter": f"(ApplicationId eq '{app_id}')", "select": [], "top": 1, "skip": 0})
    columns = [item["Column"] for item in report.get("Schema", [])]
    values = (report.get("Values") or [[]])[0]
    row = dict(zip(columns, values))
    return {"devices": {"installed": row.get("InstalledDeviceCount", 0), "failed": row.get("FailedDeviceCount", 0),
                        "pending": row.get("PendingInstallDeviceCount", 0), "notInstalled": row.get("NotInstalledDeviceCount", 0),
                        "notApplicable": row.get("NotApplicableDeviceCount", 0)},
            "users": {"installed": row.get("InstalledUserCount", 0), "failed": row.get("FailedUserCount", 0),
                      "pending": row.get("PendingInstallUserCount", 0), "notInstalled": row.get("NotInstalledUserCount", 0),
                      "notApplicable": row.get("NotApplicableUserCount", 0)}, "reportUpdatedUtc": report.get("LastUpdatedTime")}


async def install_devices(client: Any, app_id: str, *, http: httpx.AsyncClient | None = None, attempts: int = 40, delay: float = 3.0) -> list[dict[str, Any]]:
    """Per-device install state through an Intune report export job (the app's deviceStatuses endpoint is not available for Win32 apps)."""
    app_id = _guid(app_id)
    job = await client.post("/deviceManagement/reports/exportJobs", use_beta=True,
                            json={"reportName": "DeviceInstallStatusByApp", "filter": f"(ApplicationId eq '{app_id}')", "format": "csv"})
    job_id = str(job.get("id") or "")
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", job_id):
        raise AppManagementError("The report job could not be started.")
    state: dict[str, Any] = {}
    for _ in range(attempts):
        state = await client.get(f"/deviceManagement/reports/exportJobs('{job_id}')", use_beta=True)
        if state.get("status") in ("completed", "failed"):
            break
        await asyncio.sleep(delay)
    if state.get("status") != "completed":
        raise AppManagementError("The install report did not finish in time; try again shortly.")
    _validate_export_url(state.get("url", ""))
    owned = http is None
    http = http or httpx.AsyncClient(timeout=60.0)
    try:
        response = await http.get(state["url"], follow_redirects=False)
        response.raise_for_status()
    finally:
        if owned:
            await http.aclose()
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        text = archive.read(archive.namelist()[0]).decode("utf-8-sig")
    return [{"deviceName": row.get("DeviceName"), "user": row.get("UserPrincipalName") or None, "platform": row.get("Platform"),
             "appVersion": row.get("AppVersion"), "state": row.get("AppInstallState_loc") or row.get("InstallState"),
             "detail": row.get("AppInstallStateDetails_loc") or None, "errorCode": row.get("HexErrorCode") or row.get("ErrorCode") or None,
             "lastModified": (row.get("LastModifiedDateTime") or "")[:19] or None} for row in csv.DictReader(io.StringIO(text))]


async def install_status(client: Any, app_id: str, *, include_devices: bool = True, **kwargs: Any) -> dict[str, Any]:
    app_id = _guid(app_id)
    app = await client.get(f"{APPS}/{app_id}", use_beta=True)
    result: dict[str, Any] = {"app": app_summary(app), **(await install_overview(client, app_id))}
    if include_devices:
        result["deviceStates"] = await install_devices(client, app_id, **kwargs)
    return result


# ------------------------------------------------------------------------ assignments
def _target_label(target: dict[str, Any], names: dict[str, str]) -> str:
    kind = str(target.get("@odata.type") or "").rsplit(".", 1)[-1]
    if kind in ("allLicensedUsersAssignmentTarget", "allDevicesAssignmentTarget"):
        return "All users" if "Users" in kind else "All devices"
    group = target.get("groupId")
    return ("NOT " if kind.startswith("exclusion") else "") + (names.get(group) or str(group))


def describe_assignments(assignments: list[dict[str, Any]], names: dict[str, str] | None = None) -> list[str]:
    names = names or {}
    return [f"{item.get('intent')}: {_target_label(item.get('target') or {}, names)}" for item in assignments] or ["(no assignments)"]


async def get_assignments(client: Any, app_id: str) -> list[dict[str, Any]]:
    return (await client.get(f"{APPS}/{_guid(app_id)}/assignments", use_beta=True)).get("value", [])


async def resolve_group(client: Any, group: str) -> dict[str, Any]:
    """Accept a group id or exact display name; anything ambiguous is returned to the caller, never guessed."""
    group = (group or "").strip()
    if not group:
        raise AppManagementError("group is required (a group name or id).")
    if group.casefold() in BROAD_TARGETS:
        return {"id": None, "displayName": group.title(), "broad": BROAD_TARGETS[group.casefold()]}
    if GUID.match(group):
        found = await client.get(f"/groups/{group}?$select=id,displayName")
        return {"id": found["id"], "displayName": found.get("displayName"), "broad": None}
    result = await client.get(f"/groups?$filter={quote(f'displayName eq {chr(39)}{_odata_string(group)}{chr(39)}', safe='(),=')}&$select=id,displayName")
    groups = result.get("value", [])
    if not groups:
        raise AppManagementError(f"No group is named '{group}'. Use the exact name or the group id.")
    if len(groups) > 1:
        raise AppManagementError("Several groups have that name: " + ", ".join(f"{item['displayName']} ({item['id']})" for item in groups))
    return {"id": groups[0]["id"], "displayName": groups[0]["displayName"], "broad": None}


def build_assignment(intent: str, group: dict[str, Any], app_type: str, notifications: str = "", exclude: bool = False) -> dict[str, Any]:
    if intent not in INTENTS:
        raise AppManagementError("intent must be one of: " + ", ".join(INTENTS))
    if group["broad"]:
        target: dict[str, Any] = {"@odata.type": group["broad"]}
        if exclude:
            raise AppManagementError("All users and All devices cannot be excluded.")
    else:
        target = {"@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget" if exclude else "#microsoft.graph.groupAssignmentTarget", "groupId": group["id"]}
    assignment: dict[str, Any] = {"@odata.type": "#microsoft.graph.mobileAppAssignment", "intent": intent, "target": target}
    if app_type == WIN32_TYPE:
        if notifications and notifications not in NOTIFICATIONS:
            raise AppManagementError("notifications must be one of: " + ", ".join(NOTIFICATIONS))
        assignment["settings"] = {"@odata.type": "#microsoft.graph.win32LobAppAssignmentSettings", "notifications": notifications or "showAll",
                                  "deliveryOptimizationPriority": "notConfigured"}
    elif notifications:
        raise AppManagementError("Notification settings are only available on regular Win32 apps; catalog apps use Intune defaults.")
    return assignment


def _same_target(a: dict[str, Any], b: dict[str, Any]) -> bool:
    ta, tb = a.get("target") or {}, b.get("target") or {}
    return ta.get("@odata.type") == tb.get("@odata.type") and ta.get("groupId") == tb.get("groupId")


def merge_assignments(existing: list[dict[str, Any]], new: dict[str, Any], mode: str) -> list[dict[str, Any]]:
    if mode == "replace":
        return [new]
    kept = [item for item in existing if not _same_target(item, new)]
    return [{key: value for key, value in item.items() if key not in ("id", "source", "sourceId")} for item in kept] + [new]


async def group_names(client: Any, assignments: list[dict[str, Any]]) -> dict[str, str]:
    names: dict[str, str] = {}
    for item in assignments:
        group_id = (item.get("target") or {}).get("groupId")
        if group_id and group_id not in names:
            try:
                names[group_id] = (await client.get(f"/groups/{group_id}?$select=displayName")).get("displayName") or group_id
            except Exception:
                names[group_id] = group_id
    return names


async def plan_assignment(client: Any, app_id: str, group: str, intent: str, *, mode: str = "add", notifications: str = "", exclude: bool = False) -> dict[str, Any]:
    app_id = _guid(app_id)
    if mode not in ("add", "replace"):
        raise AppManagementError("mode must be 'add' (keep other assignments) or 'replace'.")
    app = await client.get(f"{APPS}/{app_id}", use_beta=True)
    target_group = await resolve_group(client, group)
    new = build_assignment(intent, target_group, app.get("@odata.type", ""), notifications, exclude)
    existing = await get_assignments(client, app_id)
    final = merge_assignments(existing, new, mode)
    names = await group_names(client, existing + final)
    if target_group["id"]:
        names[target_group["id"]] = target_group["displayName"]
    return {"app": app_summary(app), "group": target_group, "before": describe_assignments(existing, names),
            "after": describe_assignments(final, names), "assignments": final, "broad": bool(target_group["broad"]),
            "removes": [line for line in describe_assignments(existing, names) if line not in describe_assignments(final, names) and line != "(no assignments)"]}


async def apply_assignments(client: Any, app_id: str, assignments: list[dict[str, Any]]) -> dict[str, Any]:
    """Assignments are written through beta, which keeps the per-assignment settings the v1.0 call dropped."""
    await client.post(f"{APPS}/{_guid(app_id)}/assign", use_beta=True, json={"mobileAppAssignments": assignments})
    return {"status": "success", "assignments": describe_assignments(await get_assignments(client, app_id), await group_names(client, assignments))}


# ------------------------------------------------------------------------ relationships
def _relationship_key(item: dict[str, Any]) -> tuple[str, str]:
    return str(item.get("@odata.type") or ""), str(item.get("targetId") or "")


async def get_relationships(client: Any, app_id: str) -> list[dict[str, Any]]:
    items = (await client.get(f"{APPS}/{_guid(app_id)}/relationships", use_beta=True)).get("value", [])
    return [{"type": str(item.get("@odata.type") or "").rsplit(".", 1)[-1], "targetId": item.get("targetId"), "targetName": item.get("targetDisplayName"),
             "targetVersion": item.get("targetDisplayVersion"), "targetType": item.get("targetType"), "supersedenceType": item.get("supersedenceType"),
             "dependencyType": item.get("dependencyType")} for item in items]


async def set_relationships(client: Any, app_id: str, additions: list[dict[str, Any]], *, replace: bool = False) -> list[dict[str, Any]]:
    """updateRelationships replaces the whole child list, so current ones are merged in unless replace is asked for."""
    app_id = _guid(app_id)
    for item in additions:
        _guid(str(item.get("targetId")), "targetId")
    current = [] if replace else [item for item in (await client.get(f"{APPS}/{app_id}/relationships", use_beta=True)).get("value", []) if item.get("targetType") == "child"]
    keep = {_relationship_key(item): {key: item[key] for key in ("@odata.type", "targetId", "supersedenceType", "dependencyType") if key in item} for item in current}
    for item in additions:
        keep[_relationship_key(item)] = item
    await client.post(f"{APPS}/{app_id}/updateRelationships", use_beta=True, json={"relationships": list(keep.values())})
    return await get_relationships(client, app_id)


def supersedence(target_id: str, kind: str = "update") -> dict[str, Any]:
    if kind not in ("update", "replace"):
        raise AppManagementError("supersedence type must be 'update' or 'replace'.")
    return {"@odata.type": "#microsoft.graph.mobileAppSupersedence", "targetId": _guid(target_id, "targetId"), "supersedenceType": kind}


def dependency(target_id: str, kind: str = "autoInstall") -> dict[str, Any]:
    if kind not in ("detect", "autoInstall"):
        raise AppManagementError("dependency type must be 'detect' or 'autoInstall'.")
    return {"@odata.type": "#microsoft.graph.mobileAppDependency", "targetId": _guid(target_id, "targetId"), "dependencyType": kind}


# ------------------------------------------------------------------------ catalog updates
async def _catalog_apps(client: Any) -> list[dict[str, Any]]:
    return await ap._collect_pages(client, f"{APPS}?$filter=" + quote("isof('microsoft.graph.win32CatalogApp')", safe="(),=.'") + "&$top=100", max_pages=20)


async def _newest_in_branch(client: Any, package: dict[str, Any]) -> dict[str, Any] | None:
    words = re.findall(r"[A-Za-z0-9]+", str(package.get("productDisplayName") or ""))
    if not words:
        return None
    raw = await ap._collect_pages(client, "/deviceAppManagement/mobileAppCatalogPackages?$search=" + quote('"' + max(words, key=len) + '"', safe="") + "&$top=100")
    same = [item for item in raw if item.get("productId") == package.get("productId") and item.get("branchId") == package.get("branchId")]
    return max(same, key=lambda item: _version_key(item.get("versionDisplayName")), default=None)


async def check_catalog_updates(client: Any) -> dict[str, Any]:
    """Compare each catalog app with the newest catalog package of the same product and branch (matching by id, since branch names change)."""
    rows, retired = [], []
    for app in await _catalog_apps(client):
        try:
            package = await ap.catalog_get(client, app["mobileAppCatalogPackageId"])
        except Exception:
            package = None
        installed = app.get("displayVersion")
        entry = {"appId": app["id"], "name": app.get("displayName"), "installedVersion": installed, "assigned": bool(app.get("isAssigned"))}
        newest = await _newest_in_branch(client, package) if package else None
        if newest is None:
            candidates = []
            if package:
                found = await ap.catalog_search(client, package["productDisplayName"], top=5)
                candidates = [{"packageId": item["id"], "name": item["productDisplayName"], "version": item["versionDisplayName"], "branch": item.get("branchDisplayName")} for item in found["packages"]]
            retired.append({**entry, "status": "retired", "reason": "The catalog no longer lists this package; it needs replacing with a new app, not an in-place update.", "replacementCandidates": candidates})
            continue
        entry.update({"catalogVersion": newest["versionDisplayName"], "newPackageId": newest["id"]})
        entry["status"] = "update_available" if _version_key(newest["versionDisplayName"]) > _version_key(installed or package.get("versionDisplayName")) else "up_to_date"
        rows.append(entry)
    rows.sort(key=lambda row: (row["status"] != "update_available", str(row["name"]).casefold()))
    return {"count": len(rows) + len(retired), "updatesAvailable": sum(1 for row in rows if row["status"] == "update_available"), "apps": rows, "retired": retired}


async def plan_catalog_update(client: Any, app_id: str, group: str = "") -> dict[str, Any]:
    """New app body, supersedence on the old app, and which assignments it will receive (the old app's, unless a group is given)."""
    app_id = _guid(app_id)
    old = await client.get(f"{APPS}/{app_id}", use_beta=True)
    if old.get("@odata.type") != CATALOG_TYPE:
        raise AppManagementError("This is not an Enterprise App Catalog app. Only catalog apps can be updated this way.")
    package = await ap.catalog_get(client, old["mobileAppCatalogPackageId"])
    newest = await _newest_in_branch(client, package)
    if newest is None:
        raise AppManagementError("The catalog no longer lists this package, so there is nothing to update to. Search the catalog for its replacement.")
    if _version_key(newest["versionDisplayName"]) <= _version_key(old.get("displayVersion") or package.get("versionDisplayName")):
        return {"status": "up_to_date", "app": app_summary(old), "catalogVersion": newest["versionDisplayName"]}
    if group:
        assignments = [build_assignment("required", await resolve_group(client, group), CATALOG_TYPE)]
    else:
        assignments = [{key: value for key, value in item.items() if key not in ("id", "source", "sourceId", "settings")} for item in await get_assignments(client, app_id)]
    names = await group_names(client, assignments)
    return {"status": "update_available", "old": app_summary(old), "newPackage": {"id": newest["id"], "version": newest["versionDisplayName"], "branch": newest.get("branchDisplayName")},
            "assignments": assignments, "assignmentSummary": describe_assignments(assignments, names)}
