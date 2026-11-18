"""Find any app from its vendor: winget community index lookup, vendor installer download and verification."""
from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import os
import re
import socket
import sqlite3
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx
import yaml

from intune_mcp_server import app_packaging as ap

INDEX_URL = "https://cdn.winget.microsoft.com/cache/source.msix"
CDN = "https://cdn.winget.microsoft.com/cache/"
INDEX_TTL_SECONDS = 12 * 3600
MAX_INDEX_BYTES = 200 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_DOWNLOAD_BYTES = int(os.environ.get("APP_DOWNLOAD_MAX_BYTES", str(4 * 1024**3)))
USER_AGENT = "EndpointSecureOps-app-source"
PACKAGE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_\-]{0,127}$")
PRODUCT_CODE = re.compile(r"^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$")
UNINSTALL_KEY = re.compile(r"^[A-Za-z0-9 ._{}\-+()]{1,120}$")
SUPPORTED = {"msi": "msi", "wix": "msi", "burn": "burn", "inno": "inno", "nullsoft": "nsis", "exe": "exe", "msix": "msix", "appx": "msix"}
SILENT = {"inno": "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-", "nsis": "/S", "burn": "/quiet /norestart"}
TYPE_PREFERENCE = ["msi", "burn", "inno", "nsis", "exe", "msix"]


class SourceError(ValueError):
    """Operator-facing failure; never contains credentials."""


class InsecureRedirect(SourceError):
    """A download hop used plain HTTP; mirror pickers rotate, so the caller may try again."""


def version_key(version: str | None) -> tuple[int, ...]:
    match = re.search(r"\d+(?:\.\d+)*", version or "")
    return tuple(int(part) for part in match.group(0).split(".")) if match else ()


def normalize_name(value: str) -> str:
    """Drop edition/architecture decoration so 'Notepad++ (x64)' and 'Notepad++' compare equal."""
    value = re.sub(r"\((?:x64|x86|64-bit|32-bit|exe|msi|user|system installer|machine)[^)]*\)", " ", value or "", flags=re.I)
    return re.sub(r"[^a-z0-9+]+", " ", value.casefold()).strip()


# ----------------------------------------------------------------------------- winget index
def _locked(method):
    """Serialise queries: one SQLite connection is shared by the worker threads."""
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    wrapper.__doc__, wrapper.__name__ = method.__doc__, method.__name__
    return wrapper


def _like(term: str) -> str:
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class WingetIndex:
    """Local copy of Microsoft's public winget package index (a SQLite file inside source.msix)."""

    def __init__(self, cache_dir: Path | None = None, http: httpx.Client | None = None, ttl: int = INDEX_TTL_SECONDS):
        self.cache_dir = Path(cache_dir or Path(tempfile.gettempdir()) / "endpointsecureops")
        self.http, self.ttl, self._db, self._opened = http, ttl, None, 0.0
        self._lock = threading.RLock()

    @property
    def path(self) -> Path:
        return self.cache_dir / "winget_index.db"

    def _client(self) -> httpx.Client:
        return self.http or httpx.Client(timeout=120.0, headers={"User-Agent": USER_AGENT})

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    def ensure(self) -> sqlite3.Connection:
        """Open the cached index, re-downloading it once it is older than the TTL (also in a long-running server)."""
        if self._db is not None and time.time() - self._opened < self.ttl:
            return self._db
        self.close()
        fresh = self.path.exists() and time.time() - self.path.stat().st_mtime < self.ttl
        if not fresh:
            try:
                self._download()
            except Exception as error:
                if not self.path.exists():
                    raise SourceError(f"The winget package index could not be downloaded ({type(error).__name__}).") from None
        self._db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, check_same_thread=False)
        self._opened = time.time()
        return self._db

    def _download(self) -> None:
        client = self._client()
        try:
            response = client.get(INDEX_URL, follow_redirects=False)
            response.raise_for_status()
        finally:
            if self.http is None:
                client.close()
        if len(response.content) > MAX_INDEX_BYTES:
            raise SourceError("The winget index is unexpectedly large.")
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            member = next((name for name in archive.namelist() if name.endswith("index.db")), None)
            if not member or archive.getinfo(member).file_size > 1024**3:
                raise SourceError("The winget index package has no readable index.")
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(".tmp")
            temporary.write_bytes(archive.read(member))
        os.replace(temporary, self.path)

    def _manifest_path(self, db: sqlite3.Connection, rowid: int) -> str:
        parts: list[str] = []
        for _ in range(16):
            row = db.execute("select parent, pathpart from pathparts where rowid=?", (rowid,)).fetchone()
            if not row:
                break
            parts.append(row[1])
            if not row[0]:
                break
            rowid = row[0]
        return "/".join(reversed(parts))

    @_locked
    def search(self, term: str, top: int = 25) -> list[dict[str, Any]]:
        """Packages whose id, name or moniker contains the term; latest known version per package, best name match first."""
        needle = (term or "").strip()
        if not needle:
            raise SourceError("search_term is required.")
        db = self.ensure()
        pattern = _like(needle)
        rows = db.execute(
            "select i.id, n.name, v.version, m.pathpart from manifest m join ids i on i.rowid=m.id join names n on n.rowid=m.name "
            "join versions v on v.rowid=m.version left join monikers k on k.rowid=m.moniker "
            "where i.id like ? escape '\\' or n.name like ? escape '\\' or k.moniker like ? escape '\\' limit 20000", (pattern, pattern, pattern)).fetchall()
        best: dict[str, dict[str, Any]] = {}
        for package_id, name, version, pathpart in rows:
            current = best.get(package_id)
            if current is None or version_key(version) > version_key(current["version"]):
                best[package_id] = {"id": package_id, "name": name, "version": version, "_pathpart": pathpart}
        lowered = needle.casefold()

        def rank(item: dict[str, Any]) -> tuple[int, int, str]:
            name, pid = item["name"].casefold(), item["id"].casefold()
            order = 0 if name == lowered or pid == lowered else 1 if name.startswith(lowered) else 2 if lowered in name else 3
            return order, len(item["name"]), item["name"].casefold()
        ranked = sorted(best.values(), key=rank)[:top]
        return [{"id": item["id"], "name": item["name"], "latestVersion": item["version"]} for item in ranked]

    @_locked
    def find(self, package_id: str, version: str = "") -> dict[str, Any]:
        """Exact package id; the requested version, or the newest one."""
        if not PACKAGE_ID.match(package_id or ""):
            raise SourceError("winget_id must look like Publisher.Package (letters, digits, '.', '+', '_' and '-').")
        db = self.ensure()
        rows = db.execute("select n.name, v.version, m.pathpart from manifest m join ids i on i.rowid=m.id join names n on n.rowid=m.name "
                          "join versions v on v.rowid=m.version where i.id=? collate nocase", (package_id,)).fetchall()
        if not rows:
            raise SourceError(f"No winget package has the id '{package_id}'. Use source_search to find it.")
        if version:
            chosen = next((row for row in rows if row[1] == version), None)
            if chosen is None:
                raise SourceError(f"Version {version} of {package_id} is not in the index. Newest is {max(rows, key=lambda r: version_key(r[1]))[1]}.")
        else:
            chosen = max(rows, key=lambda row: version_key(row[1]))
        return {"id": package_id, "name": chosen[0], "version": chosen[1], "path": self._manifest_path(db, chosen[2])}

    @_locked
    def latest_version(self, display_name: str) -> dict[str, Any] | None:
        """Newest version of the package whose normalised name equals display_name, only when exactly one package matches."""
        wanted = normalize_name(display_name)
        if not wanted:
            return None
        db = self.ensure()
        rows = db.execute("select i.id, n.name, v.version from manifest m join ids i on i.rowid=m.id join names n on n.rowid=m.name "
                          "join versions v on v.rowid=m.version where n.name like ? escape '\\' limit 5000", (_like(display_name.split(" (")[0].strip()),)).fetchall()
        packages: dict[str, dict[str, Any]] = {}
        for package_id, name, version in rows:
            if normalize_name(name) == wanted and (package_id not in packages or version_key(version) > version_key(packages[package_id]["version"])):
                packages[package_id] = {"id": package_id, "name": name, "version": version}
        return next(iter(packages.values())) if len(packages) == 1 else None


# ----------------------------------------------------------------------------- manifests
def fetch_manifest(path: str, http: httpx.Client | None = None) -> dict[str, Any]:
    if not re.fullmatch(r"manifests/[A-Za-z0-9._+\-/]+", path or "") or ".." in path:
        raise SourceError("The manifest path from the index was not valid.")
    client = http or httpx.Client(timeout=30.0, headers={"User-Agent": USER_AGENT})
    try:
        response = client.get(CDN + path, follow_redirects=False)
        response.raise_for_status()
    finally:
        if http is None:
            client.close()
    if len(response.content) > MAX_MANIFEST_BYTES:
        raise SourceError("The package manifest is unexpectedly large.")
    manifest = yaml.safe_load(response.text)
    if not isinstance(manifest, dict):
        raise SourceError("The package manifest could not be read.")
    return manifest


def normalize_installers(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten root-level defaults into each installer entry."""
    root_switches = manifest.get("InstallerSwitches") or {}
    result = []
    for entry in manifest.get("Installers") or []:
        if not isinstance(entry, dict) or not entry.get("InstallerUrl"):
            continue
        kind = str(entry.get("InstallerType") or manifest.get("InstallerType") or "").lower()
        switches = {**root_switches, **(entry.get("InstallerSwitches") or {})}
        entries = entry.get("AppsAndFeaturesEntries") or manifest.get("AppsAndFeaturesEntries") or []
        code = entry.get("ProductCode") or manifest.get("ProductCode") or next((item.get("ProductCode") for item in entries if isinstance(item, dict) and item.get("ProductCode")), None)
        result.append({"architecture": str(entry.get("Architecture") or "neutral").lower(), "type": kind, "url": str(entry["InstallerUrl"]),
                       "sha256": str(entry.get("InstallerSha256") or "").upper() or None, "scope": str(entry.get("Scope") or manifest.get("Scope") or "").lower() or None,
                       "locale": entry.get("InstallerLocale"), "silent": switches.get("Silent"), "silentWithProgress": switches.get("SilentWithProgress"),
                       "custom": switches.get("Custom"), "productCode": str(code) if code else None,
                       "displayVersion": next((item.get("DisplayVersion") for item in entries if isinstance(item, dict) and item.get("DisplayVersion")), None),
                       "publisher": next((item.get("Publisher") for item in entries if isinstance(item, dict) and item.get("Publisher")), None)})
    return result


def select_installer(installers: list[dict[str, Any]], architecture: str = "x64") -> dict[str, Any]:
    usable = [item for item in installers if item["type"] in SUPPORTED]
    if not usable:
        kinds = sorted({item["type"] or "unknown" for item in installers})
        raise SourceError("This package has no installer type that can be deployed as an app (found: " + ", ".join(kinds) + ").")
    wanted = {"x64": ["x64", "neutral", "x86"], "x86": ["x86", "neutral"], "arm64": ["arm64", "neutral"]}.get(architecture, [architecture, "neutral"])
    pool = [item for item in usable if item["architecture"] in wanted]
    if not pool:
        raise SourceError(f"This package has no {architecture} installer.")

    def score(item: dict[str, Any]) -> tuple[int, int, int, int]:
        locale = str(item.get("locale") or "").lower()
        return (wanted.index(item["architecture"]), 0 if item.get("scope") != "user" else 1, TYPE_PREFERENCE.index(SUPPORTED[item["type"]]),
                0 if not locale or locale.startswith("en") else 1)
    return min(pool, key=score)


ALLOWED_SUFFIXES = (".msi", ".msix", ".appx", ".exe", ".msixbundle", ".appxbundle")


def name_from_url(url: str) -> str:
    """Safe local file name for a vendor download address; only installer file types are accepted."""
    name = re.sub(r"[^A-Za-z0-9._\-+ ]", "_", unquote(Path(urlsplit(url).path).name)).strip(" .")
    if Path(name).suffix.lower() not in ALLOWED_SUFFIXES:
        raise SourceError("The download address must end in an installer file name (.msi, .exe, .msix, .appx).")
    return name


def file_name_for(installer: dict[str, Any]) -> str:
    name = unquote(Path(urlsplit(installer["url"]).path).name)
    name = re.sub(r"[^A-Za-z0-9._\-+ ]", "_", name).strip(" .") or "installer"
    wanted = {"msi": ".msi", "msix": ".msix"}.get(SUPPORTED[installer["type"]], ".exe")
    return name if Path(name).suffix.lower() in ALLOWED_SUFFIXES else name + wanted


def registry_detection_rule(key: str) -> dict[str, Any]:
    """Script rule that looks for the uninstall key in both registry views, so the installer's bitness does not matter."""
    script = (f"$k='{key}'\n$roots='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'\n"
              "if ($roots | Where-Object { Test-Path (Join-Path $_ $k) }) { Write-Output 'Installed'; exit 0 }\nexit 1\n")
    return {"@odata.type": "#microsoft.graph.win32LobAppPowerShellScriptRule", "ruleType": "detection", "displayName": f"Add/Remove Programs entry {key}",
            "enforceSignatureCheck": False, "runAs32Bit": False, "scriptContent": base64.b64encode(script.encode("utf-8")).decode("ascii"),
            "operationType": "notConfigured", "operator": "notConfigured"}


def command_lines(installer: dict[str, Any], file_name: str) -> dict[str, Any]:
    """Install/uninstall commands and a detection rule from manifest facts; anything missing is reported, not guessed."""
    kind = SUPPORTED[installer["type"]]
    code = installer.get("productCode")
    guid = code if code and PRODUCT_CODE.match(code) else None
    key = code if code and UNINSTALL_KEY.match(code) else None
    custom = f" {installer['custom']}" if installer.get("custom") else ""
    out: dict[str, Any] = {"installerType": kind, "notes": []}
    if kind == "msix":
        return {**out, "basis": "MSIX/APPX line-of-business app; no commands or detection rules are needed"}
    if kind == "msi":
        out["installCommandLine"] = f'msiexec /i "{file_name}" {installer.get("silent") or "/qn /norestart"}{custom}'
    else:
        switches = installer.get("silent") or SILENT.get(kind)
        if switches:
            out["installCommandLine"] = f'"{file_name}" {switches}{custom}'
        else:
            out["notes"].append("The manifest gives no silent switches for this installer; supply silentSwitches.")
    if code and (kind in ("msi", "burn")):
        out["uninstallCommandLine"] = f'msiexec /x "{guid}" /qn /norestart' if kind == "msi" and guid else None
    if guid and kind == "msi":
        out["rules"] = [{"@odata.type": "#microsoft.graph.win32LobAppProductCodeRule", "ruleType": "detection", "productCode": guid, "productVersionOperator": "notConfigured"}]
        out["basis"] = "manifest product code"
    elif key:
        out["rules"] = [registry_detection_rule(key)]
        out["basis"] = "Add/Remove Programs entry named in the manifest, checked in both registry views"
    else:
        out["notes"].append("The manifest names no product code, so detection needs detectPath (a file that exists once installed).")
    if "uninstallCommandLine" not in out or not out["uninstallCommandLine"]:
        out.pop("uninstallCommandLine", None)
        out["notes"].append("The manifest has no uninstall command; supply uninstallCommandLine (the app's UninstallString).")
    return out


def resolve_winget(index: WingetIndex, package_id: str, version: str = "", architecture: str = "x64", *, http: httpx.Client | None = None) -> dict[str, Any]:
    """Manifest facts for one package, with no download: vendor URL and hash, commands, detection and app defaults."""
    package = index.find(package_id, version)
    manifest = fetch_manifest(package["path"], http)
    installer = select_installer(normalize_installers(manifest), architecture)
    file_name = file_name_for(installer)
    commands = command_lines(installer, file_name)
    host = urlsplit(installer["url"]).hostname
    defaults = {"displayName": manifest.get("PackageName") or package["name"], "publisher": manifest.get("Publisher") or installer.get("publisher"),
                "displayVersion": installer.get("displayVersion") or package["version"],
                "description": (manifest.get("ShortDescription") or manifest.get("Description") or manifest.get("PackageName") or "").strip()[:1500] or None,
                "informationUrl": manifest.get("PackageUrl") or manifest.get("PublisherUrl"), "privacyInformationUrl": manifest.get("PrivacyUrl")}
    for key in ("installCommandLine", "uninstallCommandLine", "rules"):
        if commands.get(key):
            defaults[key] = commands[key]
    return {"wingetId": package["id"], "version": package["version"], "architecture": installer["architecture"], "installerType": commands["installerType"],
            "fileName": file_name, "downloadUrl": installer["url"], "downloadHost": host, "sha256": installer["sha256"], "defaults": {k: v for k, v in defaults.items() if v},
            "notes": commands["notes"], "basis": commands.get("basis")}


# ----------------------------------------------------------------------------- Microsoft Store
STORE_SEARCH = "https://storeedgefd.dsx.mp.microsoft.com/v9.0/manifestSearch"
STORE_ID = re.compile(r"^[0-9A-Z]{12}$")


def store_search(term: str, top: int = 10, http: httpx.Client | None = None) -> list[dict[str, Any]]:
    """Microsoft Store apps by name (the same public search winget uses); Intune installs them as Microsoft Store apps."""
    needle = (term or "").strip()
    if not needle:
        raise SourceError("search_term is required.")
    body = {"MaximumResults": max(1, min(int(top), 25)), "Query": {"KeyWord": needle, "MatchType": "Substring"},
            "Filters": [{"PackageMatchField": "Market", "RequestMatch": {"KeyWord": "US", "MatchType": "Exact"}}]}
    client = http or httpx.Client(timeout=30.0, headers={"User-Agent": USER_AGENT})
    try:
        response = client.post(STORE_SEARCH, json=body, follow_redirects=False)
        response.raise_for_status()
        data = response.json().get("Data", [])
    except (httpx.HTTPError, ValueError):
        raise SourceError("The Microsoft Store search is not reachable right now.") from None
    finally:
        if http is None:
            client.close()
    return [{"storeId": item["PackageIdentifier"], "name": item.get("PackageName"), "publisher": item.get("Publisher")}
            for item in data if STORE_ID.match(str(item.get("PackageIdentifier") or ""))]


# ----------------------------------------------------------------------------- download
def _assert_public_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise InsecureRedirect("Installers must be downloaded over HTTPS.")
    if parts.username or parts.password:
        raise SourceError("Download addresses with embedded credentials are not allowed.")
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP)}
    except OSError:
        raise SourceError("The download host could not be resolved.") from None
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise SourceError("The download address points to a private network and was blocked.")


def looks_like_html(head: bytes) -> bool:
    start = head[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    return start.startswith((b"<!doctype html", b"<html", b"<head", b"<body"))


def download_installer(url: str, folder: Path, file_name: str, expected_sha256: str | None = None, *, http: httpx.Client | None = None, max_bytes: int | None = None,
                       attempts: int = 4) -> dict[str, Any]:
    """HTTPS download with redirect checks, an HTML guard, a size cap and a SHA-256 check against the vendor's published hash.

    Vendors that rotate mirrors (for example VideoLAN) sometimes redirect to a plain-HTTP mirror; that hop is refused and the request is retried.
    """
    for attempt in range(max(1, attempts)):
        try:
            return _download_once(url, folder, file_name, expected_sha256, http=http, max_bytes=max_bytes)
        except InsecureRedirect:
            if attempt == attempts - 1:
                raise SourceError("The vendor's download redirected to a non-HTTPS mirror every time; try again later or supply a direct https download_url.") from None
    raise SourceError("The download could not be started.")


def _download_once(url: str, folder: Path, file_name: str, expected_sha256: str | None = None, *, http: httpx.Client | None = None, max_bytes: int | None = None) -> dict[str, Any]:
    limit = max_bytes or MAX_DOWNLOAD_BYTES
    folder.mkdir(parents=True, exist_ok=True)
    target = (folder / re.sub(r"[^A-Za-z0-9._\-+ ]", "_", file_name)).resolve()
    if folder.resolve() not in target.parents:
        raise SourceError("Unsafe file name.")
    partial = target.with_name(target.name + ".part")
    client = http or httpx.Client(timeout=httpx.Timeout(60.0, read=300.0), headers={"User-Agent": USER_AGENT})
    digest = hashlib.sha256()
    size = 0
    try:
        current = url
        for _ in range(6):
            _assert_public_url(current)
            with client.stream("GET", current, follow_redirects=False) as response:
                if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("location"):
                    current = str(httpx.URL(current).join(response.headers["location"]))
                    continue
                response.raise_for_status()
                declared = int(response.headers.get("content-length") or 0)
                if declared > limit:
                    raise SourceError("The installer is larger than the allowed download size.")
                with partial.open("wb") as handle:
                    for chunk in response.iter_bytes(1024 * 1024):
                        if size == 0 and looks_like_html(chunk):
                            raise SourceError("The vendor link returned a web page instead of an installer; use the vendor's direct download link.")
                        size += len(chunk)
                        if size > limit:
                            raise SourceError("The installer is larger than the allowed download size.")
                        digest.update(chunk)
                        handle.write(chunk)
            break
        else:
            raise SourceError("The download redirected too many times.")
        if size == 0:
            raise SourceError("The download was empty.")
        actual = digest.hexdigest().upper()
        if expected_sha256 and actual != expected_sha256.upper():
            raise SourceError("The downloaded file does not match the SHA-256 the vendor published; it was discarded. The vendor may have released a newer build than the index lists.")
        os.replace(partial, target)
    except httpx.HTTPError as error:
        raise SourceError(f"The download failed ({type(error).__name__}).") from None
    finally:
        partial.unlink(missing_ok=True)
        if http is None:
            client.close()
    return {"path": str(target), "fileName": target.name, "sizeBytes": size, "sha256": actual, "sha256Verified": bool(expected_sha256)}
