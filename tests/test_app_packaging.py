import asyncio
import base64
import gc
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from intune_mcp_server import app_packaging as ap
from intune_mcp_server import server

SAS = "https://account.blob.core.windows.net/container/blob?sv=fake&sig=SECRET_SIGNATURE"


class FakeGraph:
    """Records calls and scripts the content upload states."""

    def __init__(self, fail_commit=False, uri=SAS):
        self.calls, self.fail_commit, self.uri = [], fail_commit, uri

    async def post(self, endpoint, **kwargs):
        self.calls.append(("POST", endpoint, kwargs.get("json")))
        if endpoint.endswith("/contentVersions"):
            return {"id": "ver-1"}
        if endpoint.endswith("/files"):
            return {"id": "file-1"}
        if endpoint.endswith("/mobileApps") or endpoint.endswith("createCatalogApp"):
            return {"id": "app-1"}
        return {}

    async def get(self, endpoint, **kwargs):
        self.calls.append(("GET", endpoint, None))
        if "convertFromMobileAppCatalogPackage" in endpoint:
            return {"@odata.type": "#microsoft.graph.win32CatalogApp", "id": "server-id", "displayName": "Contoso", "displayVersion": "1.0",
                    "installCommandLine": "setup.exe /S", "uninstallCommandLine": "setup.exe /U", "publishingState": "notPublished",
                    "createdDateTime": "2026-01-01T00:00:00Z", "notes": None, "detectionRules": [],
                    "rules": [{"ruleType": "detection", "path": "C:\\Contoso"}], "installExperience": {"runAsAccount": "system"}}
        if "mobileAppCatalogPackages" in endpoint:
            return {"value": [{"id": "p1", "productDisplayName": "Contoso", "secret": "x"}]} if "$search" in endpoint \
                else {"id": "p1", "productDisplayName": "Contoso", "publisherDisplayName": "Contoso Ltd"}
        committed = any(call[1].endswith("/commit") for call in self.calls)
        last_post = next((call for call in reversed(self.calls) if call[0] == "POST"), None)
        if last_post and last_post[1].endswith("/renewUpload"):
            return {"uploadState": "azureStorageUriRenewalSuccess", "azureStorageUri": self.uri}
        if committed:
            return {"uploadState": "commitFileFailed" if self.fail_commit else "commitFileSuccess"}
        return {"uploadState": "azureStorageUriRequestSuccess", "azureStorageUri": self.uri}

    async def patch(self, endpoint, **kwargs):
        self.calls.append(("PATCH", endpoint, kwargs.get("json")))
        return {}

    async def delete(self, endpoint, **kwargs):
        self.calls.append(("DELETE", endpoint, None))
        return {}


class FakeHttp:
    def __init__(self, statuses=None):
        self.requests, self.statuses = [], list(statuses or [])

    async def put(self, url, content=None, headers=None):
        self.requests.append((url, content, headers))
        return SimpleNamespace(status_code=self.statuses.pop(0) if self.statuses else 201)


def run(coroutine):
    return asyncio.run(coroutine)


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "src"
        (self.source / "sub").mkdir(parents=True)
        (self.source / "setup.cmd").write_text("@echo install")
        (self.source / "sub" / "data.bin").write_bytes(os.urandom(300_000))

    def test_publisher_id_matches_the_known_microsoft_value(self):
        publisher = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
        self.assertEqual(ap.msix_publisher_id(publisher), "8wekyb3d8bbwe")

    def test_intunewin_round_trips_and_detects_tampering(self):
        built = ap.build_intunewin(str(self.source), "setup.cmd", str(self.root / "out"))
        shown = ap.read_intunewin(built["packagePath"])
        self.assertEqual(shown["setupFile"], "setup.cmd")
        self.assertNotIn("encryptionInfo", shown)
        self.assertNotIn("encryptionKey", json.dumps(shown))
        meta = ap.read_package(Path(built["packagePath"]))
        self.assertEqual(meta["encryptionInfo"]["profileIdentifier"], "ProfileVersion1")
        encrypted, plain = self.root / "content.enc", self.root / "content.zip"
        ap.extract_encrypted_content(Path(built["packagePath"]), encrypted)
        info = ap.upload_info(meta)
        self.assertEqual(encrypted.stat().st_size, info["sizeEncrypted"])
        ap.verify_mac(encrypted, info)
        ap.decrypt_file(encrypted, plain, info)
        self.assertEqual(plain.stat().st_size, info["size"])
        with zipfile.ZipFile(plain) as archive:
            self.assertEqual(sorted(archive.namelist()), ["setup.cmd", "sub/", "sub/data.bin"])
            self.assertEqual(archive.read("sub/data.bin"), (self.source / "sub" / "data.bin").read_bytes())
        data = bytearray(encrypted.read_bytes())
        data[-1] ^= 1
        encrypted.write_bytes(bytes(data))
        with self.assertRaises(ap.PackagingError):
            ap.verify_mac(encrypted, info)

    def test_builder_rejects_traversal_overwrite_and_nested_output(self):
        (self.root / "outside.cmd").write_text("x")
        with self.assertRaises(ap.PackagingError):
            ap.build_intunewin(str(self.source), "../outside.cmd", str(self.root / "out"))
        with self.assertRaises(ap.PackagingError):
            ap.build_intunewin(str(self.source), "setup.cmd", str(self.source / "out"))
        ap.build_intunewin(str(self.source), "setup.cmd", str(self.root / "out"))
        with self.assertRaises(ap.PackagingError):
            ap.build_intunewin(str(self.source), "setup.cmd", str(self.root / "out"))
        ap.build_intunewin(str(self.source), "setup.cmd", str(self.root / "out"), overwrite=True)

    def test_path_allowlist_and_hosted_default(self):
        with patch.dict(os.environ, {"APP_PACKAGING_ROOTS": str(self.source)}):
            ap.resolve_path(str(self.source / "setup.cmd"))
            with self.assertRaises(ap.PackagingError):
                ap.resolve_path(str(self.root / "outside.cmd"), must_exist=False)
        with patch.dict(os.environ, {"WEBSITE_HOSTNAME": "example.azurewebsites.net"}, clear=False):
            os.environ.pop("APP_PACKAGING_ROOTS", None)
            with self.assertRaises(ap.PackagingError):
                ap.resolve_path(str(self.source / "setup.cmd"))

    def test_msi_inspection_reads_real_database_and_suggests_commands(self):
        try:
            import msilib
            import msilib.schema
        except ImportError:
            self.skipTest("msilib unavailable")
        path = self.root / "app.msi"
        code = "{11111111-2222-3333-4444-555555555555}"
        db = msilib.init_database(str(path), msilib.schema, "Contoso App", code, "2.3.4", "Contoso Ltd")
        db.Commit()
        del db
        gc.collect()
        details = ap.inspect_installer(str(path))
        self.assertEqual(details["architecture"], "x64")
        self.assertEqual((details["productName"], details["productVersion"], details["publisher"]), ("Contoso App", "2.3.4", "Contoso Ltd"))
        self.assertEqual(details["productCode"], code)
        suggestions = details["suggestions"]
        self.assertEqual(suggestions["installCommandLine"], 'msiexec /i "app.msi" /qn /norestart')
        self.assertEqual(suggestions["uninstallCommandLine"], f'msiexec /x "{code}" /qn /norestart')
        self.assertEqual(suggestions["detectionRules"][0]["productCode"], code)

    def test_msix_inspection_and_xml_hardening(self):
        manifest = ('<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">'
                    '<Identity Name="Contoso.App" Publisher="CN=Contoso" Version="1.2.3.4" ProcessorArchitecture="x64"/>'
                    "<Properties><DisplayName>Contoso App</DisplayName><PublisherDisplayName>Contoso</PublisherDisplayName></Properties></Package>")
        path = self.root / "app.msix"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AppxManifest.xml", manifest)
        details = ap.inspect_installer(str(path))
        self.assertEqual((details["identityName"], details["productVersion"], details["architecture"]), ("Contoso.App", "1.2.3.4", "x64"))
        self.assertEqual(len(details["publisherId"]), 13)
        evil = self.root / "evil.msix"
        with zipfile.ZipFile(evil, "w") as archive:
            archive.writestr("AppxManifest.xml", '<!DOCTYPE x [<!ENTITY a "b">]><Package/>')
        with self.assertRaises(ap.PackagingError):
            ap.inspect_installer(str(evil))

    def test_exe_inspection_identifies_installer_technology(self):
        for marker, expected, switch in ((b"Inno Setup Setup Data", "inno", "/VERYSILENT"), (b"Nullsoft Install System", "nsis", "/S"),
                                         (b".wixburn", "burn", "/quiet")):
            exe = self.root / f"{expected}.exe"
            exe.write_bytes(b"MZ" + b"\0" * 5000 + marker + b"\0" * 5000)
            with patch.object(ap, "_powershell_json", return_value={"ProductName": "Contoso", "ProductVersion": "1.0", "CompanyName": "Contoso"}):
                details = ap.inspect_installer(str(exe))
            self.assertEqual(details["installerTechnology"], expected)
            self.assertIn(switch, details["suggestions"]["installCommandLine"])
            self.assertEqual(details["suggestions"]["uninstallCommandLine"], "needs_input")
        plain = self.root / "plain.exe"
        plain.write_bytes(b"MZ" + b"\0" * 100)
        with patch.object(ap, "_powershell_json", side_effect=ap.PackagingError("x")):
            self.assertEqual(ap.inspect_installer(str(plain))["suggestions"]["installCommandLine"], "needs_input")

    def test_win32_payload_derives_msi_settings_and_reports_missing_exe_fields(self):
        msi = {"installerType": "msi", "productName": "Contoso", "productVersion": "1.0", "publisher": "Contoso Ltd", "productCode": "{A}",
               "architecture": "x64", "suggestions": ap.suggest_settings({"installerType": "msi", "productCode": "{A}"}, "c.msi")}
        body = ap.win32_payload(msi, "c.msi", "c.intunewin", {"displayName": "Override"})
        self.assertEqual(body["displayName"], "Override")
        self.assertEqual(ap.missing_win32_fields(body), [])
        exe = {"installerType": "exe", "productName": "Tool", "publisher": "Vendor", "suggestions": ap.suggest_settings({"installerType": "exe"}, "t.exe")}
        missing = ap.missing_win32_fields(ap.win32_payload(exe, "t.exe", "t.intunewin", {}))
        self.assertIn("uninstallCommandLine", missing)
        self.assertTrue(any(item.startswith("rules") for item in missing))

    def test_upload_sequence_commit_body_and_no_secret_leak(self):
        encrypted, info = self.root / "c.enc", None
        info = ap.encrypt_file(self.source / "setup.cmd", encrypted)
        graph, http = FakeGraph(), FakeHttp()
        result = run(ap.upload_app(graph, "win32LobApp", {"@odata.type": "#microsoft.graph.win32LobApp", "fileName": "s.intunewin"},
                                   encrypted, info, http=http, poll_delay=0))
        self.assertEqual((result["status"], result["appId"]), ("created", "app-1"))
        self.assertNotIn("SECRET_SIGNATURE", str(result))
        steps = [(call[0], call[1].rsplit("/", 1)[-1]) for call in graph.calls if call[0] != "GET"]
        self.assertEqual(steps, [("POST", "mobileApps"), ("POST", "contentVersions"), ("POST", "files"), ("POST", "commit"), ("PATCH", "app-1")])
        commit = next(call for call in graph.calls if call[1].endswith("/commit"))[2]["fileEncryptionInfo"]
        self.assertEqual(set(commit), {"encryptionKey", "macKey", "initializationVector", "mac", "profileIdentifier", "fileDigest", "fileDigestAlgorithm"})
        self.assertEqual(graph.calls[-1][2]["committedContentVersion"], "ver-1")
        self.assertTrue(http.requests[0][0].startswith(SAS + "&comp=block&blockid="))
        self.assertTrue(http.requests[-1][0].endswith("&comp=blocklist"))
        for _, _, headers in http.requests:
            self.assertFalse(headers and "Authorization" in headers)

    def test_failed_commit_removes_the_stub_app(self):
        encrypted = self.root / "c.enc"
        info = ap.encrypt_file(self.source / "setup.cmd", encrypted)
        graph = FakeGraph(fail_commit=True)
        with self.assertRaises(ap.PackagingError):
            run(ap.upload_app(graph, "win32LobApp", {"fileName": "s.intunewin"}, encrypted, info, http=FakeHttp(), poll_delay=0))
        self.assertEqual(graph.calls[-1][0], "DELETE")

    def test_unexpected_storage_host_is_refused_before_any_data_is_sent(self):
        encrypted = self.root / "c.enc"
        info = ap.encrypt_file(self.source / "setup.cmd", encrypted)
        http = FakeHttp()
        with self.assertRaises(ap.PackagingError):
            run(ap.upload_app(FakeGraph(uri="https://evil.example.com/x?sig=1"), "win32LobApp", {}, encrypted, info, http=http, poll_delay=0))
        self.assertEqual(http.requests, [])

    def test_expired_sas_is_renewed_during_block_upload(self):
        encrypted = self.root / "c.enc"
        info = ap.encrypt_file(self.source / "setup.cmd", encrypted)
        graph, http = FakeGraph(), FakeHttp(statuses=[403])
        run(ap.upload_app(graph, "win32LobApp", {}, encrypted, info, http=http, poll_delay=0))
        self.assertTrue(any(call[1].endswith("/renewUpload") for call in graph.calls))

    def test_catalog_search_quotes_input_and_trims_fields(self):
        graph = FakeGraph()
        result = run(ap.catalog_search(graph, "Contoso"))
        self.assertEqual(result["packages"], [{"id": "p1", "productDisplayName": "Contoso"}])
        self.assertIn("%22Contoso%22", graph.calls[0][1])
        run(ap.catalog_search(graph, 'Evil" OR "x'))
        self.assertNotIn('"Evil"', graph.calls[-1][1])
        with self.assertRaises(ap.PackagingError):
            run(ap.catalog_search(graph, product_id="x' or '1'='1"))
        with self.assertRaises(ap.PackagingError):
            run(ap.catalog_get(graph, "../mobileApps"))

    def test_catalog_search_follows_pages_ranks_by_name_and_drops_fuzzy_noise(self):
        pages = {
            "first": {"value": [{"id": "n1", "productDisplayName": "BleachBit", "publisherDisplayName": "Andrew Ziem"},
                                {"id": "c2", "productDisplayName": "Remote Desktop for AnyDesk Fans"}],
                      "@odata.nextLink": "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppCatalogPackages?$skiptoken=2"},
            "second": {"value": [{"id": "a1", "productDisplayName": "AnyDesk", "publisherDisplayName": "AnyDesk Software GmbH"},
                                 {"id": "a1", "productDisplayName": "AnyDesk", "publisherDisplayName": "AnyDesk Software GmbH"}]},
        }

        class Paged:
            config = SimpleNamespace(beta_endpoint="https://graph.microsoft.com/beta", graph_endpoint="https://graph.microsoft.com/v1.0")
            seen = []

            async def get(self, endpoint, **kwargs):
                self.seen.append(endpoint)
                return pages["second"] if "skiptoken" in endpoint else pages["first"]

        client = Paged()
        result = run(ap.catalog_search(client, "anydesk"))
        self.assertEqual([item["id"] for item in result["packages"]], ["a1", "c2"])
        self.assertEqual(len(client.seen), 2)
        self.assertTrue(client.seen[1].startswith("/deviceAppManagement/"))

    def test_names_with_plus_signs_search_on_a_plain_word_and_match_the_full_name_locally(self):
        class Plus:
            seen = []

            async def get(self, endpoint, **kwargs):
                self.seen.append(endpoint)
                if "$search=%22Notepad%22" not in endpoint:
                    raise AssertionError("Graph rejects '+', so only the plain word may be sent: " + endpoint)
                return {"value": [{"id": "n", "productDisplayName": "Notepad++", "publisherDisplayName": "Don Ho"},
                                  {"id": "t", "productDisplayName": "TED Notepad", "publisherDisplayName": "TED"}]}

        client = Plus()
        result = run(ap.catalog_search(client, "Notepad++"))
        self.assertEqual([item["id"] for item in result["packages"]], ["n"])
        with self.assertRaises(ap.PackagingError):
            run(ap.catalog_search(client, "++ --"))

    def test_catalog_search_never_follows_a_link_to_another_host(self):
        class Hostile:
            config = SimpleNamespace(beta_endpoint="https://graph.microsoft.com/beta", graph_endpoint="https://graph.microsoft.com/v1.0")
            calls = 0

            async def get(self, endpoint, **kwargs):
                self.calls += 1
                return {"value": [], "@odata.nextLink": "https://evil.example/beta/steal"}

        client = Hostile()
        result = run(ap.catalog_search(client, "anything"))
        self.assertEqual((client.calls, result["count"]), (1, 0))

    def test_catalog_search_says_so_when_nothing_matches_by_name(self):
        class Fuzzy:
            async def get(self, endpoint, **kwargs):
                return {"value": [{"id": "n1", "productDisplayName": "BleachBit", "publisherDisplayName": "Andrew Ziem"}]}

        result = run(ap.catalog_search(Fuzzy(), "Google Chrome"))
        self.assertEqual(result["count"], 0)
        self.assertIn("BleachBit", result["note"])


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "setup.cmd").write_text("@echo hi")

    def call(self, **kwargs):
        return run(server.manage_app_packaging(**kwargs))

    def test_create_actions_return_plans_and_make_no_graph_calls(self):
        graph = FakeGraph()
        with patch.object(server, "get_graph_client", return_value=graph):
            incomplete = self.call(action="create_win32_app", source_folder=str(self.root), setup_file="setup.cmd")
            self.assertIn("uninstallCommandLine", [item["setting"] for item in incomplete["needsFromYou"]])
            plan = self.call(action="create_win32_app", source_folder=str(self.root), setup_file="setup.cmd", body={
                "displayName": "Demo", "publisher": "Me", "installCommandLine": "setup.cmd", "uninstallCommandLine": "x",
                "rules": [{"@odata.type": "#microsoft.graph.win32LobAppFileSystemRule", "ruleType": "detection", "path": "C:\\a",
                           "fileOrFolderName": "b", "operationType": "exists", "operator": "notConfigured", "check32BitOn64System": False}]})
            self.assertEqual(plan["status"], "confirmation_required")
            catalog = self.call(action="create_catalog_app", catalog_package_id="p1")
            self.assertEqual(catalog["status"], "confirmation_required")
            self.assertEqual(catalog["plan"]["mobileApp"]["mobileAppCatalogPackageId"], "p1")
        self.assertFalse([call for call in graph.calls if call[0] in ("POST", "PATCH", "DELETE")])

    def test_catalog_app_is_created_from_graphs_converted_body_without_server_fields(self):
        graph = FakeGraph()
        with patch.object(server, "get_graph_client", return_value=graph):
            created = self.call(action="create_catalog_app", catalog_package_id="p1", confirm=True)
        post = next(call for call in graph.calls if call[0] == "POST" and call[1].endswith("createCatalogApp"))
        app = post[2]["mobileApp"]
        self.assertEqual((app["installCommandLine"], app["uninstallCommandLine"]), ("setup.exe /S", "setup.exe /U"))
        self.assertEqual(app["rules"][0]["path"], "C:\\Contoso")
        self.assertEqual(app["mobileAppCatalogPackageId"], "p1")
        for key in ("id", "publishingState", "createdDateTime", "notes", "detectionRules"):
            self.assertNotIn(key, app)
        self.assertEqual(created, {"id": "app-1"})

    def test_catalog_app_supersedence_is_applied_after_creation(self):
        graph = FakeGraph()
        relationship = {"@odata.type": "#microsoft.graph.mobileAppSupersedence", "targetId": "old-app", "supersedenceType": "update"}
        with patch.object(server, "get_graph_client", return_value=graph):
            self.call(action="create_catalog_app", catalog_package_id="p1", confirm=True, body={"relationships": [relationship]})
        posts = [call for call in graph.calls if call[0] == "POST"]
        self.assertTrue(posts[0][1].endswith("createCatalogApp"))
        self.assertTrue(posts[1][1].endswith("/app-1/updateRelationships"))
        self.assertEqual(posts[1][2], {"relationships": [relationship]})

    def test_confirmed_win32_build_and_upload_end_to_end(self):
        graph = FakeGraph()
        http = FakeHttp()
        original = ap.upload_app

        async def upload(client, type_name, body, encrypted, info, **kwargs):
            return await original(client, type_name, body, encrypted, info, http=http, poll_delay=0)

        rule = {"@odata.type": "#microsoft.graph.win32LobAppFileSystemRule", "ruleType": "detection", "path": "C:\\a",
                "fileOrFolderName": "b", "operationType": "exists", "operator": "notConfigured", "check32BitOn64System": False}
        with patch.object(server, "get_graph_client", return_value=graph), patch.object(ap, "upload_app", upload):
            result = self.call(action="create_win32_app", source_folder=str(self.root), setup_file="setup.cmd", confirm=True, body={
                "displayName": "Demo", "publisher": "Me", "installCommandLine": "setup.cmd", "uninstallCommandLine": "x", "rules": [rule]})
        self.assertEqual(result["status"], "created")
        created = graph.calls[0][2]
        self.assertEqual((created["fileName"], created["setupFilePath"]), ("setup.intunewin", "setup.cmd"))
        self.assertTrue(http.requests)

    def test_errors_are_reported_not_raised(self):
        self.assertIn("error", self.call(action="inspect_installer", file_path=str(self.root / "missing.msi")))
        self.assertIn("error", self.call(action="create_lob_app", file_path=str(self.root / "setup.cmd")))
        self.assertIn("Unknown action", self.call(action="nope")["error"])


class FriendlyFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "neighbour.txt").write_text("must not be packaged")

    def add(self, **kwargs):
        return run(server.manage_app_packaging(action="add_app", **kwargs))

    def make_msi(self):
        import msilib
        import msilib.schema
        path = self.root / "app.msi"
        db = msilib.init_database(str(path), msilib.schema, "Contoso App", "{11111111-2222-3333-4444-555555555555}", "2.3.4", "Contoso Ltd")
        db.Commit()
        del db
        gc.collect()
        return path

    def test_single_msi_needs_only_the_file_and_one_confirmation(self):
        msi = self.make_msi()
        graph, http, packaged = FakeGraph(), FakeHttp(), {}
        original = ap.upload_app

        async def upload(client, type_name, body, encrypted, info, **kwargs):
            plain = self.root / "plain.zip"
            ap.decrypt_file(encrypted, plain, info)
            with zipfile.ZipFile(plain) as archive:
                packaged["names"] = archive.namelist()
            return await original(client, type_name, body, encrypted, info, http=http, poll_delay=0)

        with patch.object(server, "get_graph_client", return_value=graph), patch.object(ap, "upload_app", upload):
            preview = self.add(file_path=str(msi))
            self.assertEqual(preview["status"], "confirmation_required")
            self.assertTrue(preview["nothingChangedYet"])
            text = " ".join(preview["summary"])
            for expected in ("Contoso App", "2.3.4", "Contoso Ltd", "msiexec /i", "product code", "generated automatically"):
                self.assertIn(expected, text)
            self.assertEqual(graph.calls, [])
            result = self.add(file_path=str(msi), confirm=True)
        self.assertEqual(result["status"], "created")
        self.assertEqual(packaged["names"], ["app.msi"])

    def test_exe_asks_only_for_what_it_cannot_read_and_accepts_short_hands(self):
        exe = self.root / "tool.exe"
        exe.write_bytes(b"MZ" + b"\0" * 100)
        with patch.object(ap, "_powershell_json", return_value={"ProductName": "Tool", "ProductVersion": "1.0", "CompanyName": "Vendor"}):
            asked = self.add(file_path=str(exe))
            self.assertEqual(asked["status"], "needs_input")
            self.assertEqual([item["setting"] for item in asked["needsFromYou"]],
                             ["installCommandLine", "uninstallCommandLine", "rules (at least one detection rule)"])
            self.assertTrue(all(item["howToAnswer"] for item in asked["needsFromYou"]))
            plan = self.add(file_path=str(exe), body={"silentSwitches": "/S", "uninstallCommandLine": '"C:\\Tool\\un.exe" /S',
                                                      "detectPath": "C:\\Program Files\\Tool\\tool.exe"})
        payload = plan["plan"]["appPayload"]
        self.assertEqual(payload["installCommandLine"], '"tool.exe" /S')
        rule = payload["rules"][0]
        self.assertEqual((rule["path"], rule["fileOrFolderName"], rule["operationType"], rule["ruleType"]),
                         ("C:\\Program Files\\Tool", "tool.exe", "exists", "detection"))
        self.assertNotIn("detectPath", payload)

    def test_confirmation_can_be_switched_off_for_clients_that_already_prompt(self):
        msi = self.make_msi()
        graph = FakeGraph()
        original = ap.upload_app

        async def upload(client, type_name, body, encrypted, info, **kwargs):
            return await original(client, type_name, body, encrypted, info, http=FakeHttp(), poll_delay=0)

        with patch.dict(os.environ, {"APP_PACKAGING_REQUIRE_CONFIRM": "false"}), patch.object(server, "get_graph_client", return_value=graph), \
                patch.object(ap, "upload_app", upload):
            self.assertEqual(self.add(file_path=str(msi))["status"], "created")

    def test_msix_routes_to_lob_and_catalog_name_routes_to_catalog(self):
        manifest = ('<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">'
                    '<Identity Name="Contoso.App" Publisher="CN=Contoso" Version="1.0.0.0" ProcessorArchitecture="x64"/>'
                    "<Properties><DisplayName>Contoso</DisplayName><PublisherDisplayName>Contoso</PublisherDisplayName></Properties></Package>")
        package = self.root / "app.msix"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("AppxManifest.xml", manifest)
        graph = FakeGraph()
        with patch.object(server, "get_graph_client", return_value=graph):
            lob = self.add(file_path=str(package))
            self.assertEqual(lob["plan"]["appType"], "windowsUniversalAppX")
            single = self.add(search_term="Contoso")
            self.assertEqual(single["plan"]["mobileApp"]["mobileAppCatalogPackageId"], "p1")
            self.assertIn("Microsoft supplies", " ".join(single["summary"]))
            self.assertIn("error", self.add())

    def test_several_catalog_matches_ask_once_for_a_choice(self):
        class Two(FakeGraph):
            async def get(self, endpoint, **kwargs):
                if "$search" in endpoint:
                    return {"value": [{"id": "a", "productDisplayName": "x One"}, {"id": "b", "productDisplayName": "x Two"}]}
                return {"id": endpoint.rsplit("/", 1)[-1], "productDisplayName": "Chosen"}

        with patch.object(server, "get_graph_client", return_value=Two()):
            asked = self.add(search_term="x")
            self.assertEqual((asked["status"], [item["id"] for item in asked["matches"]]), ("choose_one", ["a", "b"]))
            chosen = self.add(search_term="x", catalog_package_id="b")
            self.assertEqual(chosen["plan"]["mobileApp"]["mobileAppCatalogPackageId"], "b")


if __name__ == "__main__":
    unittest.main()
