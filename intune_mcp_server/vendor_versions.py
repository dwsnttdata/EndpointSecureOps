"""Compare installed Win32 app versions with the version the vendor publishes."""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

import httpx

USER_AGENT = "EndpointSecureOps-vendor-check"
VERSION_PATTERN = re.compile(r"\d+(?:\.\d+)+")


def parse_version(value: str | None) -> tuple[int, ...]:
    match = VERSION_PATTERN.search(value or "")
    return tuple(int(part) for part in match.group(0).split(".")) if match else ()


def compare(installed: str, latest: str) -> int:
    a, b = parse_version(installed), parse_version(latest)
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def _edge(data: Any) -> tuple[str, dict]:
    stable = next(item for item in data if item.get("Product") == "Stable")
    versions = [r["ProductVersion"] for r in stable["Releases"] if r.get("Platform") == "Windows" and r.get("Architecture") == "x64" and r.get("ProductVersion")]
    return max(versions, key=parse_version), {}


def _m365(data: Any) -> tuple[str, dict]:
    channels = {item["channelId"]: item["latestVersion"] for item in data if item.get("channelId") and item.get("latestVersion")}
    return channels["Current"], {"latestByChannel": channels}


def _github_tag(data: Any) -> tuple[str, dict]:
    return str(data["tag_name"]), {}


@dataclass(frozen=True)
class VendorSource:
    key: str
    match: Callable[[str, str], bool]
    url: str
    latest: Callable[[Any], tuple[str, dict]]
    label: str


SOURCES = [
    VendorSource("edge", lambda n, p: n == "Microsoft Edge", "https://edgeupdates.microsoft.com/api/products", _edge, "Microsoft Edge release feed (Stable, Windows x64)"),
    VendorSource("m365", lambda n, p: n.startswith("Microsoft 365 Apps"), "https://clients.config.office.net/releases/v1.0/OfficeReleases", _m365, "Microsoft Office release feed (Current Channel)"),
    VendorSource("chrome", lambda n, p: n == "Google Chrome", "https://versionhistory.googleapis.com/v1/chrome/platforms/win64/channels/stable/versions?pageSize=1", lambda d: (d["versions"][0]["version"], {}), "Google Version History API (Stable, win64)"),
    VendorSource("vscode", lambda n, p: n.startswith("Microsoft Visual Studio Code"), "https://update.code.visualstudio.com/api/releases/stable", lambda d: (d[0], {}), "VS Code update API (Stable)"),
    VendorSource("git", lambda n, p: n == "Git" and "git" in p.lower(), "https://api.github.com/repos/git-for-windows/git/releases/latest", _github_tag, "Git for Windows latest GitHub release"),
    VendorSource("notepadpp", lambda n, p: n.startswith("Notepad++"), "https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest", _github_tag, "Notepad++ latest GitHub release"),
]

SERVICE_DELIVERED = re.compile(r"^(Remote Desktop|RDP |Microsoft Intune Management Extension|Windows Autopatch|Microsoft Cloud Managed Desktop)", re.I)


def is_win32(app: dict) -> bool:
    publisher = str(app.get("publisher") or "")
    name = str(app.get("displayName") or "")
    return bool(app.get("version")) and not publisher.startswith("CN=") and not re.fullmatch(r"[A-Za-z0-9]+(?:\.[A-Za-z0-9_]+)+", name)


async def _fetch(http: httpx.AsyncClient, source: VendorSource) -> tuple[str, dict] | str:
    try:
        response = await http.get(source.url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}, follow_redirects=False)
        response.raise_for_status()
        return source.latest(response.json())
    except Exception as error:
        return f"{type(error).__name__}: {str(error)[:120]}"


async def check_vendor_versions(apps: list[dict], http: httpx.AsyncClient | None = None, search_term: str = "", index: Any = None) -> dict[str, Any]:
    """Group detected Win32 apps, then compare each version with its vendor's published latest.

    Apps without an official feed fall back to `index` (the winget community index), reported as lower confidence.
    """
    owned = http is None
    http = http or httpx.AsyncClient(timeout=20.0)
    try:
        groups: dict[tuple[str, str], dict[str, int]] = {}
        for app in apps:
            if not is_win32(app):
                continue
            name, publisher = str(app["displayName"]).strip(), str(app.get("publisher") or "").strip()
            if search_term and search_term.lower() not in name.lower():
                continue
            groups.setdefault((name, publisher), {})[app["version"]] = groups.get((name, publisher), {}).get(app["version"], 0) + int(app.get("deviceCount") or 0)
        matched = {key: next((s for s in SOURCES if s.match(*key)), None) for key in groups}
        needed = {s.key: s for s in matched.values() if s}
        fetched = dict(zip(needed, await asyncio.gather(*(_fetch(http, s) for s in needed.values()))))
        results, not_checked = [], []
        for (name, publisher), versions in sorted(groups.items()):
            source = matched[(name, publisher)]
            if source is None:
                community = None if SERVICE_DELIVERED.match(name) or len(versions) < 2 or index is None else await asyncio.to_thread(index.latest_version, name)
                if community:
                    source = VendorSource("winget", lambda n, p: False, "https://github.com/microsoft/winget-pkgs", lambda d: (community["version"], {}),
                                          f"winget community index ({community['id']}); community-maintained, can lag the vendor")
                    fetched[f"winget:{name}"] = (community["version"], {})
                    matched[(name, publisher)] = source
                    confidence = "community"
                else:
                    if len(versions) > 1:
                        reason = "Delivered by a Microsoft service rather than a downloadable release" if SERVICE_DELIVERED.match(name) else "No official machine-readable vendor version feed is registered"
                        not_checked.append({"app": name, "publisher": publisher, "reason": reason, "versionsInTenant": len(versions)})
                    continue
            else:
                confidence = "vendor"
            outcome = fetched[f"winget:{name}"] if source.key == "winget" else fetched[source.key]
            if isinstance(outcome, str):
                not_checked.append({"app": name, "publisher": publisher, "reason": f"Vendor source unreachable ({outcome})"})
                continue
            latest, extra = outcome
            channel_latest = set(extra.get("latestByChannel", {}).values())
            installed = []
            for version, devices in sorted(versions.items(), key=lambda item: parse_version(item[0]), reverse=True):
                current = compare(version, latest) >= 0 or version in channel_latest
                installed.append({"version": version, "devices": devices, "status": "current" if current else "outdated"})
            behind = sum(row["devices"] for row in installed if row["status"] == "outdated")
            results.append({"app": name, "publisher": publisher, "vendorLatest": latest, "vendorSource": source.label, "vendorUrl": source.url,
                            "confidence": confidence, **extra, "devicesBehind": behind, "status": "outdated" if behind else "current", "installed": installed})
        results.sort(key=lambda row: (-row["devicesBehind"], row["app"]))
        return {"checkedAtUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "checked": len(results),
                "outdated": sum(1 for row in results if row["status"] == "outdated"), "apps": results, "notChecked": not_checked,
                "note": "Latest versions come from the vendor feeds listed per app. Apps without an official feed are listed in notChecked, never guessed."}
    finally:
        if owned:
            await http.aclose()
