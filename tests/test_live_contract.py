"""Read-only checks of the Graph and vendor behaviors this server depends on.

Skipped unless LIVE_CONTRACT_TESTS=1, so ordinary test runs never touch a tenant:

    $env:LIVE_CONTRACT_TESTS = "1"; python -m unittest tests.test_live_contract

Every call is a GET or a report/search request; nothing is created, changed or assigned.
"""
import asyncio
import os
import unittest

LIVE = os.environ.get("LIVE_CONTRACT_TESTS") == "1"


@unittest.skipUnless(LIVE, "set LIVE_CONTRACT_TESTS=1 to run read-only checks against the configured tenant")
class LiveContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from intune_mcp_server import app_management, app_packaging, app_sources
        from intune_mcp_server.server import get_graph_client
        cls.am, cls.ap, cls.src, cls.client = app_management, app_packaging, app_sources, get_graph_client()
        cls.loop = asyncio.new_event_loop()  # the shared Graph client keeps connections bound to one loop

    @classmethod
    def tearDownClass(cls):
        cls.loop.run_until_complete(cls.client.close())
        cls.loop.close()

    def run_async(self, coro):
        return self.loop.run_until_complete(coro)

    def test_catalog_search_follows_pages_and_ranks_by_name(self):
        result = self.run_async(self.ap.catalog_search(self.client, "Notepad++", top=5))
        self.assertTrue(result["packages"], "expected Notepad++ in the Enterprise App Catalog")
        self.assertIn("notepad++", result["packages"][0]["productDisplayName"].casefold())

    def test_convert_from_catalog_package_returns_install_commands(self):
        package = self.run_async(self.ap.catalog_search(self.client, "7-Zip", top=1))["packages"][0]
        converted = self.run_async(self.ap.catalog_converted_app(self.client, package["id"]))
        self.assertTrue(converted.get("installCommandLine"))
        self.assertTrue(converted.get("rules"))

    def test_app_search_is_case_insensitive(self):
        apps = self.run_async(self.am.list_apps(self.client, 5))["apps"]
        if not apps:
            self.skipTest("tenant has no apps")
        name = apps[0]["displayName"]
        found = self.run_async(self.am.search_apps(self.client, name.upper()))
        self.assertIn(apps[0]["id"], [app["id"] for app in found["apps"]])

    def test_install_overview_report_is_available(self):
        apps = self.run_async(self.am.list_apps(self.client, 5, "win32LobApp"))["apps"]
        if not apps:
            self.skipTest("tenant has no Win32 apps")
        overview = self.run_async(self.am.install_overview(self.client, apps[0]["id"]))
        self.assertIn("installed", overview["devices"])

    def test_catalog_update_check_runs_and_classifies_every_app(self):
        result = self.run_async(self.am.check_catalog_updates(self.client))
        self.assertEqual(result["count"], len(result["apps"]) + len(result["retired"]))

    def test_winget_index_and_manifests_still_have_the_expected_shape(self):
        index = self.src.WingetIndex()
        self.addCleanup(index.close)
        found = index.search("7-Zip", top=3)
        self.assertTrue(found)
        resolved = self.src.resolve_winget(index, "7zip.7zip")
        self.assertTrue(resolved["downloadUrl"].startswith("https://"))
        self.assertEqual(len(resolved["sha256"]), 64)

    def test_store_search_still_returns_store_ids(self):
        found = self.src.store_search("Power Automate", 3)
        self.assertTrue(any(item["storeId"] == "9NFTCH6J7FHV" for item in found))

    def test_vendor_feeds_respond(self):
        from intune_mcp_server import vendor_versions as vv
        apps = [{"displayName": "Microsoft Edge", "publisher": "Microsoft", "version": "1.0.0.0", "deviceCount": 1}]
        result = self.run_async(vv.check_vendor_versions(apps))
        self.assertEqual(result["checked"], 1, result["notChecked"])


if __name__ == "__main__":
    unittest.main()
