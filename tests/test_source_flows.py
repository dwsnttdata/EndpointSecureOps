import asyncio
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from intune_mcp_server import app_packaging as ap
from intune_mcp_server import app_sources as src
from intune_mcp_server import server

MSI_URL = "https://dl.contoso.example/files/tool.msi"
RESOLVED = {"wingetId": "Contoso.Tool", "version": "2.0", "architecture": "x64", "installerType": "msi", "fileName": "tool.msi", "downloadUrl": MSI_URL,
            "downloadHost": "dl.contoso.example", "sha256": "AB" * 32, "notes": [], "basis": "manifest product code",
            "defaults": {"displayName": "Contoso Tool", "publisher": "Contoso Ltd", "installCommandLine": 'msiexec /i "tool.msi" /qn /norestart',
                         "uninstallCommandLine": 'msiexec /x "{11111111-2222-3333-4444-555555555555}" /qn /norestart',
                         "rules": [{"@odata.type": "#microsoft.graph.win32LobAppProductCodeRule", "ruleType": "detection",
                                    "productCode": "{11111111-2222-3333-4444-555555555555}", "productVersionOperator": "notConfigured"}]}}


def run(coro):
    return asyncio.run(coro)


class Graph:
    def __init__(self):
        self.calls = []

    async def post(self, endpoint, **kwargs):
        self.calls.append(("POST", endpoint, kwargs.get("json")))
        return {"id": "new-app", "displayName": "x", "publishingState": "processing"}

    async def get(self, endpoint, **kwargs):
        self.calls.append(("GET", endpoint, None))
        return {"value": []}


class SourceFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = patch.dict(os.environ, {"APP_PACKAGING_ROOTS": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def call(self, **kwargs):
        return run(server.manage_app_packaging(**kwargs))

    def fake_download(self, content=b"MZ-installer", sha_ok=True):
        def download(url, folder, name, expected, **kwargs):
            folder.mkdir(parents=True, exist_ok=True)
            if expected and not sha_ok:
                raise src.SourceError("The downloaded file does not match the SHA-256 the vendor published; it was discarded.")
            target = folder / name
            target.write_bytes(content)
            return {"path": str(target), "fileName": name, "sizeBytes": len(content), "sha256": hashlib.sha256(content).hexdigest().upper(), "sha256Verified": bool(expected)}
        return download

    def test_winget_preview_downloads_nothing_and_shows_origin_and_the_unsigned_rule(self):
        with patch.object(src, "resolve_winget", return_value=RESOLVED), patch.object(src, "download_installer") as download:
            plan = self.call(action="add_app", winget_id="Contoso.Tool")
        download.assert_not_called()
        self.assertEqual(plan["status"], "confirmation_required")
        text = " ".join(plan["summary"])
        self.assertIn("dl.contoso.example", text)
        self.assertIn("allowUnsigned", text)
        self.assertIn("Contoso Tool", text)

    def test_unsigned_installer_is_blocked_and_cleaned_up_unless_explicitly_allowed(self):
        unsigned = {"status": "NotSigned", "signer": None}
        with patch.object(src, "resolve_winget", return_value=RESOLVED), patch.object(src, "download_installer", self.fake_download()), \
                patch.object(ap, "verify_signature", return_value=unsigned):
            result = self.call(action="add_app", winget_id="Contoso.Tool", confirm=True)
        self.assertIn("not valid", result["error"])
        self.assertEqual(list(Path(self.tmp.name).glob("endpointsecureops-downloads/*")), [])

    def test_a_hash_mismatch_creates_nothing(self):
        graph = Graph()
        with patch.object(src, "resolve_winget", return_value=RESOLVED), patch.object(src, "download_installer", self.fake_download(sha_ok=False)), \
                patch.object(server, "get_graph_client", return_value=graph):
            result = self.call(action="add_app", winget_id="Contoso.Tool", confirm=True)
        self.assertIn("does not match", result["error"])
        self.assertEqual([call for call in graph.calls if call[0] == "POST"], [])

    def test_download_installer_returns_hash_signature_and_source(self):
        with patch.object(src, "resolve_winget", return_value=RESOLVED), patch.object(src, "download_installer", self.fake_download()), \
                patch.object(ap, "verify_signature", return_value={"status": "Valid", "signer": "Contoso Ltd"}):
            result = self.call(action="download_installer", winget_id="Contoso.Tool")
        self.assertEqual((result["signature"]["status"], result["sha256Verified"], result["source"]["wingetId"]), ("Valid", True, "Contoso.Tool"))
        self.assertTrue(Path(result["path"]).is_file())

    def test_download_url_must_be_https_and_an_installer_file_name(self):
        self.assertIn("https", self.call(action="add_app", download_url="http://x.example/a.exe")["error"])
        self.assertIn("installer file name", self.call(action="download_installer", download_url="https://x.example/page.html")["error"])

    def test_catalog_miss_falls_back_to_one_exact_winget_match_but_asks_when_unclear(self):
        graph = Graph()
        with patch.object(server, "get_graph_client", return_value=graph), patch.object(server.WINGET_INDEX, "search") as search, \
                patch.object(src, "resolve_winget", return_value=RESOLVED):
            search.return_value = [{"id": "Contoso.Tool", "name": "Contoso Tool", "latestVersion": "2.0"}]
            plan = self.call(action="add_app", search_term="Contoso Tool")
            self.assertEqual(plan["status"], "confirmation_required")
            search.return_value = [{"id": "A.One", "name": "Tool One", "latestVersion": "1"}, {"id": "B.Two", "name": "Tool Two", "latestVersion": "1"}]
            choice = self.call(action="add_app", search_term="Tool")
            self.assertEqual((choice["status"], [m["id"] for m in choice["matches"]]), ("choose_one", ["A.One", "B.Two"]))
            search.return_value = []
            self.assertIn("download_url", self.call(action="add_app", search_term="Nothing Here")["error"])

    def test_store_apps_preview_then_create_a_wingetapp_with_no_commands(self):
        graph = Graph()
        listing = [{"storeId": "9NFTCH6J7FHV", "name": "Power Automate", "publisher": "Microsoft Corporation"}]
        with patch.object(server, "get_graph_client", return_value=graph), patch.object(src, "store_search", return_value=listing):
            plan = self.call(action="add_app", store_id="9nftch6j7fhv")
            self.assertEqual(plan["status"], "confirmation_required")
            self.assertEqual(graph.calls, [])
            self.call(action="add_app", store_id="9NFTCH6J7FHV", confirm=True)
        body = next(call for call in graph.calls if call[0] == "POST")[2]
        self.assertEqual((body["@odata.type"], body["packageIdentifier"]), ("#microsoft.graph.winGetApp", "9NFTCH6J7FHV"))
        self.assertNotIn("installCommandLine", body)

    def test_store_ids_are_validated_before_any_lookup(self):
        for bad in ("short", "x' or 1=1--", "9NFTCH6J7FH!"):
            self.assertIn("12-character", self.call(action="add_app", store_id=bad)["error"])
        with patch.object(src, "store_search", return_value=[]):
            self.assertIn("No Microsoft Store app", self.call(action="add_app", store_id="ZZZZZZZZZZZZ")["error"])

    def test_source_search_reports_each_source_and_survives_one_failing(self):
        with patch.object(server, "get_graph_client", return_value=Graph()), patch.object(server.WINGET_INDEX, "search", return_value=[{"id": "A.B", "name": "A", "latestVersion": "1"}]), \
                patch.object(src, "store_search", side_effect=src.SourceError("Store down")):
            result = self.call(action="source_search", search_term="a")
        self.assertEqual((len(result["winget"]), result["store"], result["storeError"]), (1, [], "Store down"))


if __name__ == "__main__":
    unittest.main()
