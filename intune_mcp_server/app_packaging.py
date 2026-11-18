"""Windows app packaging: .intunewin builder, installer inspection, Intune content upload, app catalog."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import ntpath
import os
import re
import shutil
import subprocess
import tempfile
import warnings
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import httpx
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CHUNK = 4 * 1024 * 1024
BLOCK_SIZE = 6 * 1024 * 1024
MAX_SOURCE_BYTES = 8 * 1024**3
CONTENT_NAME = "IntunePackage.intunewin"
CONTENT_ENTRY = "IntuneWinPackage/Contents/" + CONTENT_NAME
METADATA_ENTRY = "IntuneWinPackage/Metadata/Detection.xml"
BLOB_HOST_SUFFIXES = (".blob.core.windows.net", ".blob.core.usgovcloudapi.net", ".blob.core.chinacloudapi.cn")
LOB_TYPES = {".msi": "windowsMobileMSI", ".msix": "windowsUniversalAppX", ".appx": "windowsUniversalAppX",
             ".msixbundle": "windowsUniversalAppX", ".appxbundle": "windowsUniversalAppX"}
SUCCESS_CODES = [(0, "success"), (1707, "success"), (3010, "softReboot"), (1641, "hardReboot"), (1618, "retry")]


class PackagingError(ValueError):
    """Operator-facing failure; the message never contains credentials or upload URIs."""


# --------------------------------------------------------------------------- paths
def resolve_path(raw: str, *, must_exist: bool = True, kind: str = "file") -> Path:
    """Resolve a local path, enforcing APP_PACKAGING_ROOTS (mandatory on hosted deployments)."""
    if not raw or not str(raw).strip():
        raise PackagingError("A path is required.")
    path = Path(str(raw).strip()).expanduser().resolve(strict=False)
    roots = os.environ.get("APP_PACKAGING_ROOTS", "").strip()
    if roots:
        allowed = [Path(item).expanduser().resolve(strict=False) for item in roots.split(os.pathsep) if item.strip()]
        if not any(path == root or root in path.parents for root in allowed):
            raise PackagingError("Path is outside APP_PACKAGING_ROOTS.")
    elif os.environ.get("WEBSITE_HOSTNAME"):
        raise PackagingError("Set APP_PACKAGING_ROOTS before using file packaging on a hosted deployment.")
    if must_exist and not (path.is_file() if kind == "file" else path.is_dir()):
        raise PackagingError(f"The {kind} was not found: {path.name}")
    return path


def _inside(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


def require_confirmation() -> bool:
    """One preview-then-confirm step is the default; APP_PACKAGING_REQUIRE_CONFIRM=false skips it."""
    return os.environ.get("APP_PACKAGING_REQUIRE_CONFIRM", "true").strip().lower() not in ("false", "0", "no")


def stage_single_file(file: Path, destination: Path) -> Path:
    """Copy one installer into its own folder so only that file is packaged, not its neighbours."""
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(file, destination / file.name)
    return destination


# ------------------------------------------------------------------- encryption
def encrypt_file(source: Path, target: Path) -> dict[str, Any]:
    """Encrypt to MAC(32) + IV(16) + AES-256-CBC ciphertext, the ProfileVersion1 layout Intune expects."""
    key, mac_key, iv = os.urandom(32), os.urandom(32), os.urandom(16)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    padder = padding.PKCS7(128).padder()
    digest = hashlib.sha256()
    mac = hmac.new(mac_key, iv, hashlib.sha256)
    size = 0
    with source.open("rb") as reader, target.open("wb") as writer:
        writer.write(b"\0" * 32 + iv)
        while chunk := reader.read(CHUNK):
            size += len(chunk)
            digest.update(chunk)
            block = encryptor.update(padder.update(chunk))
            mac.update(block)
            writer.write(block)
        block = encryptor.update(padder.finalize()) + encryptor.finalize()
        mac.update(block)
        writer.write(block)
        tag = mac.digest()
        writer.seek(0)
        writer.write(tag)
    b64 = lambda value: base64.b64encode(value).decode("ascii")
    return {"encryptionKey": b64(key), "macKey": b64(mac_key), "initializationVector": b64(iv), "mac": b64(tag),
            "profileIdentifier": "ProfileVersion1", "fileDigest": b64(digest.digest()), "fileDigestAlgorithm": "SHA256",
            "size": size, "sizeEncrypted": target.stat().st_size}


def verify_mac(encrypted: Path, info: dict[str, Any]) -> None:
    """Check the HMAC of IV + ciphertext against the metadata before any upload."""
    mac = hmac.new(base64.b64decode(info["macKey"]), digestmod=hashlib.sha256)
    with encrypted.open("rb") as reader:
        tag = reader.read(32)
        while chunk := reader.read(CHUNK):
            mac.update(chunk)
    expected = base64.b64decode(info["mac"])
    if not (hmac.compare_digest(mac.digest(), tag) and hmac.compare_digest(tag, expected)):
        raise PackagingError("The encrypted package failed its integrity check (MAC mismatch).")


def decrypt_file(encrypted: Path, target: Path, info: dict[str, Any]) -> None:
    verify_mac(encrypted, info)
    with encrypted.open("rb") as reader, target.open("wb") as writer:
        reader.seek(32)
        iv = reader.read(16)
        decryptor = Cipher(algorithms.AES(base64.b64decode(info["encryptionKey"])), modes.CBC(iv)).decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        while chunk := reader.read(CHUNK):
            writer.write(unpadder.update(decryptor.update(chunk)))
        writer.write(unpadder.update(decryptor.finalize()) + unpadder.finalize())


# ----------------------------------------------------------------- .intunewin I/O
def _zip_folder(source: Path, target: Path) -> None:
    total = sum(item.stat().st_size for item in source.rglob("*") if item.is_file() and not item.is_symlink())
    if total > MAX_SOURCE_BYTES:
        raise PackagingError("The source folder exceeds the 8 GiB Win32 app limit.")
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        for item in sorted(source.rglob("*")):
            if not item.is_symlink():
                archive.write(item, item.relative_to(source).as_posix())


def _detection_xml(name: str, setup_file: str, info: dict[str, Any]) -> str:
    fields = "".join(f"<{tag}>{escape(str(info[key]))}</{tag}>" for tag, key in (
        ("EncryptionKey", "encryptionKey"), ("MacKey", "macKey"), ("InitializationVector", "initializationVector"),
        ("Mac", "mac"), ("ProfileIdentifier", "profileIdentifier"), ("FileDigest", "fileDigest"),
        ("FileDigestAlgorithm", "fileDigestAlgorithm")))
    return ('<?xml version="1.0" encoding="utf-8"?><ApplicationInfo ToolVersion="1.8.4.0">'
            f"<Name>{escape(name)}</Name><UnencryptedContentSize>{info['size']}</UnencryptedContentSize>"
            f"<FileName>{CONTENT_NAME}</FileName><SetupFile>{escape(setup_file)}</SetupFile>"
            f"<EncryptionInfo>{fields}</EncryptionInfo></ApplicationInfo>")


def _safe_xml(data: bytes) -> ET.Element:
    if b"<!doctype" in data.lower() or b"<!entity" in data.lower():
        raise PackagingError("XML with a DOCTYPE or entity declaration was rejected.")
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        raise PackagingError("The XML metadata is not valid.") from None


def build_intunewin(source_folder: str, setup_file: str, output_folder: str, *, overwrite: bool = False) -> dict[str, Any]:
    return build_package(resolve_path(source_folder, kind="dir"), setup_file,
                         resolve_path(output_folder, must_exist=False, kind="dir"), overwrite=overwrite)


def build_package(source: Path, setup_file: str, output: Path, *, overwrite: bool = False) -> dict[str, Any]:
    source, output = source.resolve(strict=False), output.resolve(strict=False)
    if _inside(output, source):
        raise PackagingError("The output folder must not be inside the source folder.")
    setup = (source / setup_file).resolve(strict=False)
    if not setup_file.strip() or not _inside(setup, source) or not setup.is_file():
        raise PackagingError("setup_file must be an existing file inside the source folder.")
    relative_setup = setup.relative_to(source).as_posix()
    output.mkdir(parents=True, exist_ok=True)
    package = output / (setup.stem + ".intunewin")
    if package.exists() and not overwrite:
        raise PackagingError(f"{package.name} already exists; pass overwrite=True to replace it.")
    with tempfile.TemporaryDirectory(dir=output) as work_dir:
        work = Path(work_dir)
        _zip_folder(source, work / "content.zip")
        info = encrypt_file(work / "content.zip", work / CONTENT_NAME)
        with zipfile.ZipFile(work / "package.zip", "w", zipfile.ZIP_STORED, allowZip64=True) as archive:
            archive.write(work / CONTENT_NAME, CONTENT_ENTRY)
            archive.writestr(METADATA_ENTRY, _detection_xml(setup.name, relative_setup, info))
        os.replace(work / "package.zip", package)
    return {"packagePath": str(package), "setupFile": relative_setup, "unencryptedSize": info["size"],
            "encryptedSize": info["sizeEncrypted"], "packageSize": package.stat().st_size}


def read_intunewin(path: str) -> dict[str, Any]:
    meta = read_package(resolve_path(path))
    # Keys are only needed internally for upload; never return them to the client.
    return {key: value for key, value in meta.items() if key != "encryptionInfo"} | {"encryption": "present (keys not shown)"}


def read_package(package: Path) -> dict[str, Any]:
    """Read Detection.xml from an existing .intunewin without extracting the payload."""
    try:
        with zipfile.ZipFile(package) as archive:
            names = set(archive.namelist())
            if not {CONTENT_ENTRY, METADATA_ENTRY} <= names:
                raise PackagingError("This is not a valid .intunewin package.")
            if archive.getinfo(METADATA_ENTRY).file_size > 1024 * 1024:
                raise PackagingError("Detection.xml is unexpectedly large.")
            root = _safe_xml(archive.read(METADATA_ENTRY))
            encrypted_size = archive.getinfo(CONTENT_ENTRY).file_size
    except zipfile.BadZipFile:
        raise PackagingError("This is not a valid .intunewin package.") from None
    text = lambda tag: (root.findtext(tag) or "").strip()
    keys = {"encryptionKey": "EncryptionInfo/EncryptionKey", "macKey": "EncryptionInfo/MacKey",
            "initializationVector": "EncryptionInfo/InitializationVector", "mac": "EncryptionInfo/Mac",
            "profileIdentifier": "EncryptionInfo/ProfileIdentifier", "fileDigest": "EncryptionInfo/FileDigest",
            "fileDigestAlgorithm": "EncryptionInfo/FileDigestAlgorithm"}
    info = {key: text(tag) for key, tag in keys.items()}
    if not all(info.values()) or not text("UnencryptedContentSize").isdigit():
        raise PackagingError("Detection.xml is missing required encryption metadata.")
    return {"packagePath": str(package), "name": text("Name"), "setupFile": text("SetupFile"),
            "unencryptedSize": int(text("UnencryptedContentSize")), "encryptedSize": encrypted_size,
            "encryptionInfo": info}


def upload_info(meta: dict[str, Any]) -> dict[str, Any]:
    return {**meta["encryptionInfo"], "size": meta["unencryptedSize"], "sizeEncrypted": meta["encryptedSize"]}


def extract_encrypted_content(package: Path, target: Path) -> None:
    with zipfile.ZipFile(package) as archive, archive.open(CONTENT_ENTRY) as reader, target.open("wb") as writer:
        shutil.copyfileobj(reader, writer, CHUNK)


# ------------------------------------------------------------ installer inspection
def msix_publisher_id(publisher: str) -> str:
    """13-character package publisher ID derived from the Publisher distinguished name."""
    bits = "".join(f"{byte:08b}" for byte in hashlib.sha256(publisher.encode("utf-16-le")).digest()[:8]) + "0"
    alphabet = "0123456789abcdefghjkmnpqrstvwxyz"
    return "".join(alphabet[int(bits[index:index + 5], 2)] for index in range(0, 65, 5))


def _powershell_json(script: str, path: Path) -> dict[str, Any]:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        raise PackagingError("PowerShell is required for this inspection on this platform.")
    # An inherited PSModulePath from PowerShell 7 stops Windows PowerShell 5.1 from loading its own modules.
    env = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
    result = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True,
                            timeout=60, env={**env, "WISE_INSPECT_PATH": str(path)})
    if result.returncode != 0 or not result.stdout.strip():
        raise PackagingError("The installer could not be read.")
    return json.loads(result.stdout)


_MSI_COM = ("$i=New-Object -ComObject WindowsInstaller.Installer;$t=$i.GetType();"
            "$d=$t.InvokeMember('OpenDatabase','InvokeMethod',$null,$i,@($env:WISE_INSPECT_PATH,0));"
            "$v=$d.GetType().InvokeMember('OpenView','InvokeMethod',$null,$d,@('SELECT Property, Value FROM Property'));"
            "$v.GetType().InvokeMember('Execute','InvokeMethod',$null,$v,$null)|Out-Null;$o=@{};"
            "while($r=$v.GetType().InvokeMember('Fetch','InvokeMethod',$null,$v,$null)){"
            "$o[$r.GetType().InvokeMember('StringData','GetProperty',$null,$r,1)]="
            "$r.GetType().InvokeMember('StringData','GetProperty',$null,$r,2)};$o|ConvertTo-Json -Compress")


def _msi_properties(path: Path) -> tuple[dict[str, str], str]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            import msilib
        database = msilib.OpenDatabase(str(path), msilib.MSIDBOPEN_READONLY)
        view = database.OpenView("SELECT Property, Value FROM Property")
        view.Execute(None)
        props: dict[str, str] = {}
        while (record := view.Fetch()) is not None:
            props[record.GetString(1)] = record.GetString(2)
        view.Close()
        try:
            template = database.GetSummaryInformation(0).GetProperty(7) or ""
            if isinstance(template, bytes):
                template = template.decode("utf-8", errors="replace")
        except Exception:
            template = ""
        return props, template
    except ImportError:
        return _powershell_json(_MSI_COM, path), ""
    except Exception:
        raise PackagingError("The MSI database could not be read.") from None


def _inspect_msi(path: Path) -> dict[str, Any]:
    props, template = _msi_properties(path)
    arch = "x64" if "x64" in template.lower() or "amd64" in template.lower() else "x86" if "intel" in template.lower() else None
    return {"installerType": "msi", "productName": props.get("ProductName"), "productVersion": props.get("ProductVersion"),
            "publisher": props.get("Manufacturer"), "productCode": props.get("ProductCode"),
            "upgradeCode": props.get("UpgradeCode"), "architecture": arch}


def _inspect_msix(path: Path) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(path) as archive:
            names = {name.lower(): name for name in archive.namelist()}
            bundle = "appxmetadata/appxbundlemanifest.xml" in names
            member = names.get("appxmetadata/appxbundlemanifest.xml" if bundle else "appxmanifest.xml")
            if not member or archive.getinfo(member).file_size > 2 * 1024 * 1024:
                raise PackagingError("No readable package manifest was found.")
            root = _safe_xml(archive.read(member))
    except zipfile.BadZipFile:
        raise PackagingError("The MSIX/APPX package is not a valid zip archive.") from None
    local = lambda element: element.tag.rsplit("}", 1)[-1]
    identity = next((element for element in root.iter() if local(element) == "Identity"), None)
    if identity is None:
        raise PackagingError("The package manifest has no Identity element.")
    display = next((element.text for element in root.iter() if local(element) == "DisplayName" and element.text), None)
    publisher = identity.get("Publisher", "")
    return {"installerType": "msixbundle" if bundle else "msix", "identityName": identity.get("Name"),
            "publisherDistinguishedName": publisher, "publisherId": msix_publisher_id(publisher) if publisher else None,
            "productVersion": identity.get("Version"), "architecture": identity.get("ProcessorArchitecture") or "neutral",
            "productName": display if display and not display.startswith("ms-resource:") else identity.get("Name"),
            "publisher": next((element.text for element in root.iter() if local(element) == "PublisherDisplayName" and element.text), None)}


_EXE_MARKERS = (("burn", (b".wixburn", b"WixBurn")), ("inno", (b"Inno Setup Setup Data", b"JR.Inno.Setup")),
                ("nsis", (b"Nullsoft Install System", b"NullsoftInst")), ("installshield", (b"InstallShield",)))
_SILENT = {"inno": "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-", "nsis": "/S", "burn": "/quiet /norestart",
           "installshield": '/s /v"/qn /norestart"'}


def _exe_technology(path: Path) -> str | None:
    found: set[str] = set()
    overlap, scanned = 64, 0
    with path.open("rb") as reader:
        tail = b""
        while (chunk := reader.read(CHUNK)) and scanned < 256 * 1024 * 1024:
            window = tail + chunk
            for name, markers in _EXE_MARKERS:
                if any(marker in window for marker in markers):
                    found.add(name)
            tail, scanned = window[-overlap:], scanned + len(chunk)
    return next((name for name, _ in _EXE_MARKERS if name in found), None)


def _inspect_exe(path: Path) -> dict[str, Any]:
    script = ("$i=[System.Diagnostics.FileVersionInfo]::GetVersionInfo($env:WISE_INSPECT_PATH);"
              "@{ProductName=$i.ProductName;ProductVersion=$i.ProductVersion;CompanyName=$i.CompanyName}|ConvertTo-Json -Compress")
    try:
        version = _powershell_json(script, path)
    except PackagingError:
        version = {}
    return {"installerType": "exe", "productName": version.get("ProductName") or path.stem,
            "productVersion": version.get("ProductVersion"), "publisher": version.get("CompanyName"),
            "installerTechnology": _exe_technology(path), "technologyConfidence": "heuristic"}


def inspect_installer(path: str) -> dict[str, Any]:
    """Read installer metadata and suggest install, uninstall and detection settings."""
    file = resolve_path(path)
    suffix = file.suffix.lower()
    if suffix == ".msi":
        details = _inspect_msi(file)
    elif suffix in LOB_TYPES:
        details = _inspect_msix(file)
    elif suffix == ".exe":
        details = _inspect_exe(file)
    else:
        raise PackagingError("Supported installers: .msi, .msix, .appx, .msixbundle, .appxbundle, .exe.")
    details.update({"fileName": file.name, "sizeBytes": file.stat().st_size, "signature": verify_signature(file),
                    "suggestions": suggest_settings(details, file.name)})
    return details


def verify_signature(path: Path) -> dict[str, Any]:
    """Authenticode status and signer via Windows PowerShell; reported as unverified elsewhere, never assumed valid."""
    script = ("$s=Get-AuthenticodeSignature -LiteralPath $env:WISE_INSPECT_PATH;"
              "@{Status=[string]$s.Status;Subject=[string]$s.SignerCertificate.Subject}|ConvertTo-Json -Compress")
    try:
        data = _powershell_json(script, path)
    except PackagingError:
        return {"status": "unverified", "reason": "Authenticode verification needs Windows PowerShell on this host."}
    signer = re.search(r"CN=([^,]+)", data.get("Subject") or "")
    if not data.get("Status"):
        return {"status": "unverified", "reason": "The signature check returned no result on this host."}
    return {"status": data.get("Status"), "signer": signer.group(1).strip('" ') if signer else None}


def _msi_detection_rule(code: str, version: str | None) -> dict[str, Any]:
    """Product code at this version or newer, so a device already on a newer build counts as installed."""
    rule = {"@odata.type": "#microsoft.graph.win32LobAppProductCodeRule", "ruleType": "detection", "productCode": code,
            "productVersionOperator": "notConfigured"}
    if version:
        rule.update({"productVersionOperator": "greaterThanOrEqual", "productVersion": version})
    return rule


def suggest_settings(details: dict[str, Any], file_name: str) -> dict[str, Any]:
    """Install/uninstall/detection suggestions; anything not derivable is reported as needs_input."""
    kind = details["installerType"]
    if kind == "msi" and details.get("productCode"):
        code = details["productCode"]
        return {"installCommandLine": f'msiexec /i "{file_name}" /qn /norestart',
                "uninstallCommandLine": f'msiexec /x "{code}" /qn /norestart', "basis": "derived from MSI properties",
                "detectionRules": [_msi_detection_rule(code, details.get("productVersion"))]}
    if kind == "exe":
        switches = _SILENT.get(details.get("installerTechnology") or "")
        return {"installCommandLine": f'"{file_name}" {switches}' if switches else "needs_input",
                "uninstallCommandLine": "needs_input",
                "detectionRules": "needs_input",
                "basis": "heuristic" if switches else "installer technology not recognised",
                "notes": ["Confirm the silent switches on a test device before deployment.",
                          "Uninstall and detection cannot be derived from an EXE; read the UninstallString and "
                          "DisplayVersion from the registry (or the installed file version) after a test install."]}
    return {"basis": "MSIX/APPX line-of-business apps need no command lines or detection rules"}


# ------------------------------------------------------------------- app payloads
def win32_payload(inspection: dict[str, Any] | None, setup_file: str, package_name: str, overrides: dict[str, Any]) -> dict[str, Any]:
    """Win32 app body: defaults, plus MSI-derived settings (if available), overridden by the caller's body.

    Short-hands in the body: detectPath (file or folder that exists once installed) and silentSwitches.
    """
    inspection = inspection or {}
    overrides = dict(overrides)
    detect_path, switches = overrides.pop("detectPath", None), overrides.pop("silentSwitches", None)
    suggestions = inspection.get("suggestions", {})
    body: dict[str, Any] = {
        "@odata.type": "#microsoft.graph.win32LobApp", "displayName": inspection.get("productName") or Path(setup_file).stem,
        "description": inspection.get("productName") or Path(setup_file).stem, "publisher": inspection.get("publisher") or "Not specified",
        "displayVersion": inspection.get("productVersion"), "fileName": package_name, "setupFilePath": setup_file,
        "applicableArchitectures": inspection.get("architecture") or "x64", "minimumSupportedWindowsRelease": "1607",
        "installExperience": {"@odata.type": "#microsoft.graph.win32LobAppInstallExperience", "runAsAccount": "system",
                              "deviceRestartBehavior": "basedOnReturnCode", "maxRunTimeInMinutes": 60},
        "returnCodes": [{"@odata.type": "#microsoft.graph.win32LobAppReturnCode", "returnCode": code, "type": kind}
                        for code, kind in SUCCESS_CODES]}
    for key in ("installCommandLine", "uninstallCommandLine"):
        if suggestions.get(key) not in (None, "needs_input"):
            body[key] = suggestions[key]
    if isinstance(suggestions.get("detectionRules"), list):
        body["rules"] = suggestions["detectionRules"]
    if inspection.get("installerType") == "msi" and inspection.get("productCode"):
        body["msiInformation"] = {"@odata.type": "#microsoft.graph.win32LobAppMsiInformation", "productCode": inspection["productCode"],
                                  "productVersion": inspection.get("productVersion"), "upgradeCode": inspection.get("upgradeCode"),
                                  "requiresReboot": False, "packageType": "perMachine", "productName": inspection.get("productName"),
                                  "publisher": inspection.get("publisher")}
    body.update({key: value for key, value in overrides.items() if key != "@odata.type"})
    name = Path(setup_file).name
    if switches and "installCommandLine" not in overrides:
        body["installCommandLine"] = (f'msiexec /i "{name}" {switches}' if name.lower().endswith(".msi") else f'"{name}" {switches}')
    if detect_path and "rules" not in overrides:
        folder, leaf = ntpath.split(str(detect_path).rstrip("\\/"))
        body["rules"] = [{"@odata.type": "#microsoft.graph.win32LobAppFileSystemRule", "ruleType": "detection", "path": folder,
                          "fileOrFolderName": leaf, "operationType": "exists", "operator": "notConfigured", "check32BitOn64System": False}]
    return {key: value for key, value in body.items() if value is not None}


def missing_win32_fields(body: dict[str, Any]) -> list[str]:
    missing = [key for key in ("displayName", "publisher", "installCommandLine", "uninstallCommandLine") if not body.get(key)]
    if not any(rule.get("ruleType") == "detection" for rule in body.get("rules", []) if isinstance(rule, dict)):
        missing.append("rules (at least one detection rule)")
    return missing


_NEEDS = {
    "installCommandLine": ("the silent install command", 'give silentSwitches, for example "/S", or the full installCommandLine'),
    "uninstallCommandLine": ("how to uninstall it", 'the application\'s UninstallString, for example "C:\\Program Files\\App\\uninstall.exe" /S'),
    "rules (at least one detection rule)": ("how Intune can tell it is installed", 'give detectPath, for example "C:\\Program Files\\App\\app.exe"'),
    "displayName": ("the app name", "give displayName"), "publisher": ("the publisher", "give publisher")}


def needs_input(missing: list[str], suggestions: Any = None) -> dict[str, Any]:
    """Ask only for what could not be read from the installer, with an example for each answer."""
    return {"status": "needs_input",
            "message": f"I could not read {len(missing)} setting(s) from the installer. Reply with these in body and I will continue.",
            "needsFromYou": [{"setting": key, "why": _NEEDS.get(key, (key, ""))[0], "howToAnswer": _NEEDS.get(key, (key, ""))[1]} for key in missing],
            "suggestions": suggestions}


def _describe_rule(rule: dict[str, Any]) -> str:
    if rule.get("scriptContent"):
        return f"script check: {rule.get('displayName') or 'custom PowerShell rule'}"
    if rule.get("productCode"):
        return f"MSI product code {rule['productCode']}"
    if "fileOrFolderName" in rule:
        return f"{rule.get('operationType', 'exists')}: {ntpath.join(rule.get('path') or '', rule['fileOrFolderName'])}"
    return rule.get("keyPath") or rule.get("@odata.type", "custom rule").rsplit(".", 1)[-1]


def describe_win32(payload: dict[str, Any]) -> list[str]:
    experience = payload.get("installExperience", {})
    detection = "; ".join(_describe_rule(rule) for rule in payload.get("rules", []) if rule.get("ruleType") == "detection")
    return [f"Create Win32 app '{payload['displayName']}' {payload.get('displayVersion') or ''} by {payload['publisher']}".replace("  ", " "),
            f"Install: {payload['installCommandLine']}", f"Uninstall: {payload['uninstallCommandLine']}", f"Detected by: {detection}",
            f"Runs as {experience.get('runAsAccount', 'system')}; restart: {experience.get('deviceRestartBehavior', 'basedOnReturnCode')}",
            "The package is built and encrypted for you; hashes, keys and sizes are generated automatically."]


def describe_lob(type_name: str, payload: dict[str, Any]) -> list[str]:
    kind = "MSI" if type_name == "windowsMobileMSI" else "MSIX/APPX"
    return [f"Create {kind} line-of-business app '{payload['displayName']}' {payload.get('productVersion') or ''} by {payload['publisher']}".replace("  ", " "),
            "The file is encrypted and uploaded for you; hashes, keys and sizes are generated automatically."]


def lob_payload(inspection: dict[str, Any], overrides: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    type_name = LOB_TYPES[Path(inspection["fileName"]).suffix.lower()]
    common = {"displayName": inspection.get("productName"), "publisher": inspection.get("publisher") or "Unknown",
              "fileName": inspection["fileName"], "description": inspection.get("productName")}
    if type_name == "windowsMobileMSI":
        extra = {"productCode": inspection.get("productCode"), "productVersion": inspection.get("productVersion"),
                 "ignoreVersionDetection": False, "commandLine": "", "requiresReboot": False}
    else:
        arch = (inspection.get("architecture") or "neutral").lower()
        extra = {"applicableArchitectures": arch if arch in ("x86", "x64", "arm", "arm64", "neutral") else "neutral",
                 "applicableDeviceTypes": "desktop", "identityName": inspection.get("identityName"),
                 "identityPublisherHash": inspection.get("publisherId"), "identityResourceIdentifier": "",
                 "isBundle": inspection["installerType"] == "msixbundle",
                 "minimumSupportedOperatingSystem": {"@odata.type": "microsoft.graph.windowsMinimumOperatingSystem", "v10_0": True}}
    body = {"@odata.type": f"#microsoft.graph.{type_name}", **common, **extra}
    body.update({key: value for key, value in overrides.items() if key != "@odata.type"})
    return type_name, {key: value for key, value in body.items() if value is not None}


# ----------------------------------------------------------------- Intune upload
def _check_blob_uri(uri: str) -> None:
    parts = urlsplit(uri)
    if parts.scheme != "https" or not (parts.hostname or "").endswith(BLOB_HOST_SUFFIXES):
        raise PackagingError("Graph returned an unexpected storage location; the upload was stopped.")


def _with_query(uri: str, query: str) -> str:
    return uri + ("&" if "?" in uri else "?") + query


async def _wait_for_file(client: Any, endpoint: str, success: set[str], failure: set[str], attempts: int, delay: float) -> dict[str, Any]:
    for _ in range(attempts):
        file = await client.get(endpoint, use_beta=True)
        state = file.get("uploadState")
        if state in success:
            return file
        if state in failure:
            raise PackagingError(f"Intune reported the upload state '{state}'.")
        await asyncio.sleep(delay)
    raise PackagingError("Timed out waiting for Intune to process the upload.")


async def _put_blocks(http: Any, uri: str, path: Path, renew: Any) -> None:
    block_ids: list[str] = []
    with path.open("rb") as reader:
        while chunk := reader.read(BLOCK_SIZE):
            block_id = base64.b64encode(f"block-{len(block_ids):08d}".encode()).decode()
            for attempt in range(4):
                response = await http.put(_with_query(uri, "comp=block&blockid=" + quote(block_id, safe="")), content=chunk)
                if response.status_code in (200, 201):
                    break
                if response.status_code == 403 and attempt < 3:
                    uri = await renew()
                elif response.status_code in (429, 500, 502, 503, 504) and attempt < 3:
                    await asyncio.sleep(2 ** attempt)
                else:
                    raise PackagingError(f"Storage upload failed (HTTP {response.status_code}).")
            else:
                raise PackagingError("Storage upload failed after retries.")
            block_ids.append(block_id)
    body = '<?xml version="1.0" encoding="utf-8"?><BlockList>' + "".join(f"<Latest>{item}</Latest>" for item in block_ids) + "</BlockList>"
    response = await http.put(_with_query(uri, "comp=blocklist"), content=body.encode(),
                              headers={"x-ms-blob-content-type": "application/octet-stream", "Content-Type": "application/xml"})
    if response.status_code not in (200, 201):
        raise PackagingError(f"Storage block list commit failed (HTTP {response.status_code}).")


async def upload_app(client: Any, type_name: str, body: dict[str, Any], encrypted: Path, info: dict[str, Any],
                     *, http: Any = None, poll_delay: float = 2.0) -> dict[str, Any]:
    """Create the app, upload its encrypted content, commit it, and publish the committed content version."""
    owns_http = http is None
    http = http or httpx.AsyncClient(timeout=120.0)
    app_id = ""
    try:
        app = await client.post("/deviceAppManagement/mobileApps", use_beta=True, json=body)
        app_id = app["id"]
        base = f"/deviceAppManagement/mobileApps/{app_id}/microsoft.graph.{type_name}/contentVersions"
        version = (await client.post(base, use_beta=True, json={}))["id"]
        file = await client.post(f"{base}/{version}/files", use_beta=True, json={
            "@odata.type": "#microsoft.graph.mobileAppContentFile", "name": body.get("fileName") or CONTENT_NAME,
            "size": info["size"], "sizeEncrypted": info["sizeEncrypted"], "manifest": None, "isDependency": False})
        endpoint = f"{base}/{version}/files/{file['id']}"
        ready = await _wait_for_file(client, endpoint, {"azureStorageUriRequestSuccess"},
                                     {"azureStorageUriRequestFailed", "azureStorageUriRequestTimedOut"}, 90, poll_delay)
        _check_blob_uri(ready["azureStorageUri"])

        async def renew() -> str:
            await client.post(f"{endpoint}/renewUpload", use_beta=True, json={})
            renewed = await _wait_for_file(client, endpoint, {"azureStorageUriRenewalSuccess"},
                                           {"azureStorageUriRenewalFailed", "azureStorageUriRenewalTimedOut"}, 90, poll_delay)
            _check_blob_uri(renewed["azureStorageUri"])
            return renewed["azureStorageUri"]

        await _put_blocks(http, ready["azureStorageUri"], encrypted, renew)
        encryption = {key: info[key] for key in ("encryptionKey", "macKey", "initializationVector", "mac",
                                                 "profileIdentifier", "fileDigest", "fileDigestAlgorithm")}
        await client.post(f"{endpoint}/commit", use_beta=True, json={"fileEncryptionInfo": encryption})
        await _wait_for_file(client, endpoint, {"commitFileSuccess"}, {"commitFileFailed", "commitFileTimedOut"}, 150, poll_delay)
        await client.patch(f"/deviceAppManagement/mobileApps/{app_id}", use_beta=True,
                           json={"@odata.type": f"#microsoft.graph.{type_name}", "committedContentVersion": version})
        return {"status": "created", "appId": app_id, "contentVersionId": version, "appType": type_name,
                "sizeBytes": info["size"], "sizeEncryptedBytes": info["sizeEncrypted"]}
    except Exception:
        if app_id:
            try:
                await client.delete(f"/deviceAppManagement/mobileApps/{app_id}", use_beta=True)
            except Exception:
                pass
        raise
    finally:
        if owns_http:
            await http.aclose()


# ------------------------------------------------------------------ app catalog
CATALOG = "/deviceAppManagement/mobileAppCatalogPackages"


def _catalog_item(item: dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "productId", "productDisplayName", "publisherDisplayName", "versionDisplayName", "branchDisplayName",
            "applicableArchitectures", "packageAutoUpdateCapable")
    return {key: item.get(key) for key in keys if key in item}


def search_word(term: str) -> str:
    """Longest run of letters and digits; Graph's $search cannot take '+', '#' and similar characters."""
    words = re.findall(r"[A-Za-z0-9]+", term or "")
    return max(words, key=len) if words else ""


async def _collect_pages(client: Any, endpoint: str, max_pages: int = 10) -> list[dict[str, Any]]:
    """Follow @odata.nextLink; only Graph's own beta/v1.0 links are ever followed."""
    prefixes = tuple(str(getattr(getattr(client, "config", None), name, "")).rstrip("/") for name in ("beta_endpoint", "graph_endpoint"))
    items: list[dict[str, Any]] = []
    for _ in range(max_pages):
        result = await client.get(endpoint, use_beta=True)
        items.extend(result.get("value", []))
        link = result.get("@odata.nextLink") or ""
        prefix = next((p for p in prefixes if p and link.startswith(p + "/")), None)
        if not prefix:
            break
        endpoint = link[len(prefix):]
    return items


def _catalog_rank(item: dict[str, Any], needle: str) -> int | None:
    name = str(item.get("productDisplayName") or "").casefold()
    publisher = str(item.get("publisherDisplayName") or "").casefold()
    if name == needle:
        return 0
    if name.startswith(needle):
        return 1
    if needle in name:
        return 2
    return 3 if needle in publisher else None


async def catalog_search(client: Any, term: str = "", product_id: str = "", top: int = 25) -> dict[str, Any]:
    top = max(1, min(int(top), 100))
    if product_id:
        if not all(ch.isalnum() or ch in "._-" for ch in product_id):
            raise PackagingError("product_id contains unsupported characters.")
        items = await _collect_pages(client, f"{CATALOG}?$filter={quote(f'productId eq {chr(39)}{product_id}{chr(39)}', safe='(),=')}&$top=100", max_pages=3)
        return {"count": len(items), "packages": [_catalog_item(item) for item in items][:top]}
    needle = term.replace('"', " ").strip()
    if not needle:
        raise PackagingError("Provide search_term or a product id.")
    # $search rejects characters such as '+', so Graph gets the longest plain word and the full term is matched locally.
    word = search_word(needle)
    if not word:
        raise PackagingError("The search term needs at least one letter or digit.")
    try:
        found = await _collect_pages(client, f"{CATALOG}?$search={quote(chr(34) + word + chr(34), safe='')}&$top=100")
    except Exception as error:
        raise PackagingError(f"The catalog query failed: {error}") from None
    unique = {item.get("id"): item for item in found if item.get("id")}
    ranked = sorted(((rank, item) for item in unique.values() if (rank := _catalog_rank(item, needle.casefold())) is not None),
                    key=lambda pair: (pair[0], str(pair[1].get("productDisplayName")).casefold(), str(pair[1].get("branchDisplayName") or "")))
    packages = [_catalog_item(item) for _, item in ranked][:top]
    result: dict[str, Any] = {"count": len(packages), "packages": packages}
    if not packages:
        related = sorted({str(item.get("productDisplayName")) for item in unique.values() if item.get("productDisplayName")})[:10]
        result["note"] = "No catalog app has this name or publisher." + (f" Fuzzy matches elsewhere in their descriptions: {', '.join(related)}." if related else "")
    return result


async def catalog_get(client: Any, package_id: str) -> dict[str, Any]:
    if not package_id or not all(ch.isalnum() or ch in "._-" for ch in package_id):
        raise PackagingError("catalog_package_id is required and may contain only letters, digits, '.', '_' and '-'.")
    return await client.get(f"{CATALOG}/{package_id}", use_beta=True)


async def catalog_converted_app(client: Any, package_id: str) -> dict[str, Any]:
    """Graph fills in install/uninstall commands, detection rules and install experience for a catalog package."""
    if not package_id or not all(ch.isalnum() or ch in "._-" for ch in package_id):
        raise PackagingError("catalog_package_id is required and may contain only letters, digits, '.', '_' and '-'.")
    return await client.get(f"/deviceAppManagement/mobileApps/convertFromMobileAppCatalogPackage(mobileAppCatalogPackageId='{package_id}')", use_beta=True)


SERVER_MANAGED = {"@odata.context", "id", "createdDateTime", "lastModifiedDateTime", "publishingState", "uploadState", "committedContentVersion",
                  "isAssigned", "dependentAppCount", "supersedingAppCount", "supersededAppCount", "size"}


def catalog_app_payload(package: dict[str, Any], overrides: dict[str, Any], converted: dict[str, Any] | None = None) -> dict[str, Any]:
    """Body for the documented createCatalogApp action; `converted` is Graph's own pre-filled app."""
    base = {key: value for key, value in (converted or {}).items() if key not in SERVER_MANAGED and value not in (None, [], {})}
    mobile_app = {"@odata.type": "#microsoft.graph.win32CatalogApp", "displayName": package.get("productDisplayName"),
                  "description": package.get("productDisplayName"), "publisher": package.get("publisherDisplayName"),
                  "mobileAppCatalogPackageId": package.get("id"), **base, **overrides.get("mobileApp", {})}
    return {"mobileApp": {key: value for key, value in mobile_app.items() if value is not None},
            "relationships": overrides.get("relationships", []), "mobileAppAssignments": overrides.get("mobileAppAssignments", [])}


async def create_catalog_app(client: Any, package_id: str, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create a catalog app from Graph's converted body, then apply relationships (createCatalogApp ignores them)."""
    overrides = overrides or {}
    package = await catalog_get(client, package_id)
    package.setdefault("id", package_id)
    payload = catalog_app_payload(package, overrides, await catalog_converted_app(client, package_id))
    created = await client.post("/deviceAppManagement/mobileApps/createCatalogApp", use_beta=True, json=payload)
    if payload.get("relationships") and created.get("id"):
        await client.post(f"/deviceAppManagement/mobileApps/{created['id']}/updateRelationships", use_beta=True,
                          json={"relationships": payload["relationships"]})
    return created


STORE_ID_PATTERN = re.compile(r"^[0-9A-Z]{12}$")


def store_app_payload(store_id: str, name: str, publisher: str | None, overrides: dict[str, Any]) -> dict[str, Any]:
    """Microsoft Store app (winGetApp): Intune installs, updates, uninstalls and detects it, so no commands or rules are needed."""
    if not STORE_ID_PATTERN.match(store_id or ""):
        raise PackagingError("store_id must be the 12-character Microsoft Store ID, for example 9NFTCH6J7FHV.")
    account = str(overrides.pop("runAsAccount", "system")).lower()
    if account not in ("system", "user"):
        raise PackagingError("runAsAccount must be 'system' or 'user'.")
    body = {"@odata.type": "#microsoft.graph.winGetApp", "displayName": name, "description": name, "publisher": publisher or "Microsoft Store",
            "packageIdentifier": store_id, "installExperience": {"@odata.type": "microsoft.graph.winGetAppInstallExperience", "runAsAccount": account}}
    body.update({key: value for key, value in overrides.items() if key not in ("@odata.type", "packageIdentifier")})
    return body


async def create_store_app(client: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return await client.post("/deviceAppManagement/mobileApps", use_beta=True, json=payload)
