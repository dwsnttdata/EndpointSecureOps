import io
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import httpx

from intune_mcp_server import app_sources as src

MANIFEST = """
PackageName: Contoso Tool
Publisher: Contoso Ltd
ShortDescription: Does tool things.
PackageUrl: https://contoso.example/tool
InstallerType: exe
Installers:
- Architecture: x86
  InstallerUrl: https://dl.contoso.example/tool-x86.exe
  InstallerSha256: AAAA
- Architecture: x64
  InstallerType: inno
  InstallerUrl: https://dl.contoso.example/files/tool%20setup.exe
  InstallerSha256: BBBB
  ProductCode: Contoso Tool_is1
- Architecture: x64
  InstallerType: msi
  InstallerUrl: https://dl.contoso.example/tool.msi
  InstallerSha256: CCCC
  ProductCode: '{11111111-2222-3333-4444-555555555555}'
- Architecture: arm64
  InstallerType: zip
  InstallerUrl: https://dl.contoso.example/tool.zip
  InstallerSha256: DDDD
"""


def build_index(path: Path) -> None:
    db = sqlite3.connect(path)
    db.executescript("""
        create table ids(id text); create table names(name text); create table versions(version text); create table monikers(moniker text);
        create table pathparts(parent integer, pathpart text);
        create table manifest(id integer, name integer, moniker integer, version integer, channel integer, pathpart integer, hash blob);
    """)
    db.execute("insert into pathparts(rowid,parent,pathpart) values (1,null,'manifests'),(2,1,'c'),(3,2,'Contoso'),(4,3,'Tool'),(5,4,'2.0'),(6,5,'abcd')")
    db.execute("insert into pathparts(rowid,parent,pathpart) values (7,4,'1.0'),(8,7,'ef01')")
    for number, (pid, name) in enumerate([("Contoso.Tool", "Contoso Tool"), ("Contoso.ToolPlus", "Contoso Tool Plus"), ("Other.App", "Unrelated")], start=1):
        db.execute("insert into ids(rowid,id) values (?,?)", (number, pid))
        db.execute("insert into names(rowid,name) values (?,?)", (number, name))
    db.execute("insert into versions(rowid,version) values (1,'1.0'),(2,'2.0'),(3,'10.0'),(4,'9.9')")
    db.execute("insert into monikers(rowid,moniker) values (1,'contosotool')")
    db.execute("insert into manifest(id,name,moniker,version,pathpart) values (1,1,1,1,8),(1,1,1,2,6),(1,1,1,3,6),(2,2,null,4,6),(3,3,null,2,6)")
    db.commit()
    db.close()


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        build_index(Path(self.tmp.name) / "winget_index.db")
        self.index = src.WingetIndex(Path(self.tmp.name), ttl=10**9)
        self.addCleanup(self.index.close)

    def test_search_ranks_exact_name_first_and_returns_the_newest_version_numerically(self):
        found = self.index.search("contoso tool")
        self.assertEqual([item["id"] for item in found], ["Contoso.Tool", "Contoso.ToolPlus"])
        self.assertEqual(found[0]["latestVersion"], "10.0")

    def test_search_treats_wildcards_literally(self):
        self.assertEqual(self.index.search("%"), [])
        self.assertEqual(self.index.search("_ontoso"), [])
        with self.assertRaises(src.SourceError):
            self.index.search("  ")

    def test_find_picks_newest_by_number_not_text_and_resolves_the_manifest_path(self):
        package = self.index.find("contoso.tool")
        self.assertEqual((package["version"], package["path"]), ("10.0", "manifests/c/Contoso/Tool/2.0/abcd"))
        self.assertEqual(self.index.find("Contoso.Tool", "1.0")["path"], "manifests/c/Contoso/Tool/1.0/ef01")

    def test_find_rejects_unknown_versions_and_malformed_ids(self):
        with self.assertRaises(src.SourceError):
            self.index.find("Contoso.Tool", "3.0")
        with self.assertRaises(src.SourceError):
            self.index.find("Nope.Nothing")
        with self.assertRaises(src.SourceError):
            self.index.find("x'; drop table ids;--")

    def test_latest_version_only_answers_when_the_name_is_unambiguous(self):
        self.assertEqual(self.index.latest_version("Contoso Tool (x64)")["version"], "10.0")
        self.assertIsNone(self.index.latest_version("Unknown product"))

    def test_stale_index_is_downloaded_and_a_failed_refresh_keeps_the_old_copy(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("Public/index.db", (Path(self.tmp.name) / "winget_index.db").read_bytes())
        http = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=buffer.getvalue())))
        fresh = src.WingetIndex(Path(self.tmp.name) / "new", http=http)
        self.addCleanup(fresh.close)
        self.assertTrue(fresh.search("contoso"))
        failing = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(500)))
        stale = src.WingetIndex(Path(self.tmp.name), http=failing, ttl=0)
        self.addCleanup(stale.close)
        self.assertTrue(stale.search("contoso"))


class ManifestTests(unittest.TestCase):
    def installers(self):
        return src.normalize_installers(src.yaml.safe_load(MANIFEST))

    def test_root_level_type_is_inherited_and_entries_are_flattened(self):
        items = self.installers()
        self.assertEqual([(i["architecture"], i["type"]) for i in items], [("x86", "exe"), ("x64", "inno"), ("x64", "msi"), ("arm64", "zip")])

    def test_msi_is_preferred_over_exe_for_the_same_architecture(self):
        choice = src.select_installer(self.installers(), "x64")
        self.assertEqual((choice["type"], choice["sha256"]), ("msi", "CCCC"))

    def test_architecture_without_a_deployable_installer_is_an_error(self):
        with self.assertRaises(src.SourceError):
            src.select_installer(self.installers(), "arm64")

    def test_msi_commands_and_version_free_detection_come_from_the_manifest(self):
        choice = src.select_installer(self.installers(), "x64")
        lines = src.command_lines(choice, src.file_name_for(choice))
        self.assertEqual(lines["installCommandLine"], 'msiexec /i "tool.msi" /qn /norestart')
        self.assertEqual(lines["uninstallCommandLine"], 'msiexec /x "{11111111-2222-3333-4444-555555555555}" /qn /norestart')
        self.assertEqual(lines["rules"][0]["productCode"], "{11111111-2222-3333-4444-555555555555}")

    def test_exe_with_an_uninstall_key_gets_a_two_view_script_rule_and_no_guessed_uninstall(self):
        import base64
        inno = [i for i in self.installers() if i["type"] == "inno"][0]
        lines = src.command_lines(inno, src.file_name_for(inno))
        self.assertIn("/VERYSILENT", lines["installCommandLine"])
        self.assertNotIn("uninstallCommandLine", lines)
        self.assertTrue(any("uninstall" in note.lower() for note in lines["notes"]))
        self.assertFalse(any("detectPath" in note for note in lines["notes"]))
        rule = lines["rules"][0]
        self.assertTrue(rule["@odata.type"].endswith("win32LobAppPowerShellScriptRule"))
        script = base64.b64decode(rule["scriptContent"]).decode()
        self.assertIn("WOW6432Node", script)
        self.assertIn("$k='Contoso Tool_is1'", script)

    def test_exe_without_any_product_code_asks_for_detectPath(self):
        lines = src.command_lines({"type": "nullsoft", "architecture": "x64", "silent": None, "custom": None, "productCode": None}, "tool.exe")
        self.assertEqual(lines["installCommandLine"], '"tool.exe" /S')
        self.assertNotIn("rules", lines)
        self.assertTrue(any("detectPath" in note for note in lines["notes"]))

    def test_unsafe_uninstall_keys_never_reach_the_detection_script(self):
        lines = src.command_lines({"type": "inno", "architecture": "x64", "silent": None, "custom": None, "productCode": "x'; Remove-Item C:\\ -Recurse; '"}, "t.exe")
        self.assertNotIn("rules", lines)

    def test_file_names_are_decoded_and_sanitised(self):
        self.assertEqual(src.file_name_for({"url": "https://x.example/a%20b/../evil%2Fname.exe", "type": "exe"}), "evil_name.exe")
        with self.assertRaises(src.SourceError):
            src.name_from_url("https://x.example/page.html")

    def test_manifest_paths_must_stay_inside_manifests(self):
        for bad in ("../etc/passwd", "manifests/../x", "other/x", ""):
            with self.assertRaises(src.SourceError):
                src.fetch_manifest(bad)

    def test_resolve_winget_builds_app_defaults(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        build_index(Path(tmp.name) / "winget_index.db")
        http = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, text=MANIFEST)))
        index = src.WingetIndex(Path(tmp.name), ttl=10**9)
        self.addCleanup(index.close)
        resolved = src.resolve_winget(index, "Contoso.Tool", http=http)
        self.assertEqual((resolved["installerType"], resolved["downloadHost"], resolved["sha256"]), ("msi", "dl.contoso.example", "CCCC"))
        self.assertEqual((resolved["defaults"]["displayName"], resolved["defaults"]["publisher"]), ("Contoso Tool", "Contoso Ltd"))


class DownloadTests(unittest.TestCase):
    PAYLOAD = b"MZ" + b"\x00" * 5000

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name) / "dl"
        patcher = patch.object(src, "_assert_public_url", lambda url: None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def client(self, handler):
        return httpx.Client(transport=httpx.MockTransport(handler))

    def test_good_download_is_hash_verified_and_written_atomically(self):
        import hashlib
        digest = hashlib.sha256(self.PAYLOAD).hexdigest()
        result = src.download_installer("https://v.example/a.exe", self.folder, "a.exe", digest, http=self.client(lambda r: httpx.Response(200, content=self.PAYLOAD)))
        self.assertTrue(result["sha256Verified"])
        self.assertEqual(Path(result["path"]).read_bytes(), self.PAYLOAD)
        self.assertEqual(list(self.folder.glob("*.part")), [])

    def test_hash_mismatch_discards_the_file(self):
        with self.assertRaisesRegex(src.SourceError, "does not match"):
            src.download_installer("https://v.example/a.exe", self.folder, "a.exe", "00" * 32, http=self.client(lambda r: httpx.Response(200, content=self.PAYLOAD)))
        self.assertEqual(list(self.folder.iterdir()), [])

    def test_a_web_page_is_refused_like_videolans_mirror_picker(self):
        page = b"    <!DOCTYPE html>\n<html><head></head></html>"
        with self.assertRaisesRegex(src.SourceError, "web page"):
            src.download_installer("https://v.example/a.exe", self.folder, "a.exe", None, http=self.client(lambda r: httpx.Response(200, content=page)))
        self.assertEqual(list(self.folder.iterdir()), [])

    def test_size_cap_and_empty_downloads_are_refused(self):
        with self.assertRaisesRegex(src.SourceError, "larger"):
            src.download_installer("https://v.example/a.exe", self.folder, "a.exe", None, http=self.client(lambda r: httpx.Response(200, content=self.PAYLOAD)), max_bytes=100)
        with self.assertRaisesRegex(src.SourceError, "empty"):
            src.download_installer("https://v.example/a.exe", self.folder, "a.exe", None, http=self.client(lambda r: httpx.Response(200, content=b"")))

    def test_redirects_are_followed_one_hop_at_a_time_and_capped(self):
        def handler(request):
            if request.url.path == "/start":
                return httpx.Response(302, headers={"location": "https://cdn.example/final.exe"})
            return httpx.Response(200, content=self.PAYLOAD)
        result = src.download_installer("https://v.example/start", self.folder, "a.exe", None, http=self.client(handler))
        self.assertEqual(result["sizeBytes"], len(self.PAYLOAD))
        with self.assertRaisesRegex(src.SourceError, "too many"):
            src.download_installer("https://v.example/loop", self.folder, "b.exe", None, http=self.client(lambda r: httpx.Response(302, headers={"location": "https://v.example/loop"})))

    def test_file_name_cannot_escape_the_download_folder(self):
        result = src.download_installer("https://v.example/a.exe", self.folder, "..\\..\\evil.exe", None, http=self.client(lambda r: httpx.Response(200, content=self.PAYLOAD)))
        self.assertEqual(Path(result["path"]).parent, self.folder.resolve())

    def test_http_errors_are_reported_without_the_url(self):
        with self.assertRaisesRegex(src.SourceError, "failed"):
            src.download_installer("https://v.example/a.exe", self.folder, "a.exe", None, http=self.client(lambda r: httpx.Response(404)))


class MirrorRetryTests(unittest.TestCase):
    """Uses the real URL check; only DNS is faked, so a plain-HTTP hop is genuinely refused."""
    PAYLOAD = b"MZ" + b"\x00" * 2000

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = patch.object(src.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))])
        patcher.start()
        self.addCleanup(patcher.stop)

    def client(self, redirects_to_http):
        starts = []

        def handler(request):
            if request.url.path == "/start":
                starts.append(1)
                bad = len(starts) <= redirects_to_http
                return httpx.Response(302, headers={"location": ("http://" if bad else "https://") + "mirror.example/a.exe"})
            return httpx.Response(200, content=self.PAYLOAD)
        return httpx.Client(transport=httpx.MockTransport(handler)), starts

    def test_a_rotating_mirror_that_redirects_to_plain_http_is_retried(self):
        http, starts = self.client(redirects_to_http=2)
        result = src.download_installer("https://v.example/start", Path(self.tmp.name), "a.exe", None, http=http)
        self.assertEqual((result["sizeBytes"], len(starts)), (len(self.PAYLOAD), 3))

    def test_a_vendor_that_only_ever_redirects_to_http_fails_with_a_clear_message(self):
        http, starts = self.client(redirects_to_http=99)
        with self.assertRaisesRegex(src.SourceError, "non-HTTPS mirror"):
            src.download_installer("https://v.example/start", Path(self.tmp.name), "a.exe", None, http=http, attempts=3)
        self.assertEqual(len(starts), 3)
        self.assertEqual(list(Path(self.tmp.name).iterdir()), [])


class UrlSafetyTests(unittest.TestCase):
    def test_only_public_https_addresses_are_allowed(self):
        for bad in ("http://v.example/a.exe", "https://user:pw@v.example/a.exe", "ftp://v.example/a.exe"):
            with self.assertRaises(src.SourceError):
                src._assert_public_url(bad)
        with patch.object(src.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.5", 443))]):
            with self.assertRaisesRegex(src.SourceError, "private"):
                src._assert_public_url("https://intranet.example/a.exe")
        with patch.object(src.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]):
            with self.assertRaises(src.SourceError):
                src._assert_public_url("https://localhost.example/a.exe")
        with patch.object(src.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]):
            src._assert_public_url("https://v.example/a.exe")


if __name__ == "__main__":
    unittest.main()
