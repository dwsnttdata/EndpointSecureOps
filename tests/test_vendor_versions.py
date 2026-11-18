import asyncio
import unittest

import httpx

from intune_mcp_server import vendor_versions as vv

FEEDS = {
    "edgeupdates.microsoft.com": [{"Product": "Stable", "Releases": [
        {"Platform": "Windows", "Architecture": "x64", "ProductVersion": "157.0.4341.60"},
        {"Platform": "Windows", "Architecture": "x64", "ProductVersion": "157.0.4300.10"},
        {"Platform": "Linux", "Architecture": "x64", "ProductVersion": "999.0.0.0"}]}],
    "clients.config.office.net": [{"channelId": "Current", "latestVersion": "16.0.20527.20196"},
                                  {"channelId": "MonthlyEnterprise", "latestVersion": "16.0.20527.20194"},
                                  {"channelId": "SemiAnnual", "latestVersion": "16.0.19725.20730"}],
    "api.github.com": {"tag_name": "v2.56.1.windows.1"},
}


def handler(request: httpx.Request) -> httpx.Response:
    if request.url.host == "versionhistory.googleapis.com":
        return httpx.Response(500)
    return httpx.Response(200, json=FEEDS[request.url.host])


APPS = [
    {"displayName": "Microsoft Edge", "publisher": "Microsoft Corporation", "version": "157.0.4341.60", "deviceCount": 3},
    {"displayName": "Microsoft Edge", "publisher": "Microsoft Corporation", "version": "156.0.1.1", "deviceCount": 10},
    {"displayName": "Microsoft 365 Apps for enterprise - en-us", "publisher": "Microsoft Corporation", "version": "16.0.20527.20194", "deviceCount": 4},
    {"displayName": "Microsoft 365 Apps for enterprise - en-us", "publisher": "Microsoft Corporation", "version": "16.0.20326.20142", "deviceCount": 2},
    {"displayName": "Git", "publisher": "The Git Development Community", "version": "2.55.0", "deviceCount": 2},
    {"displayName": "Google Chrome", "publisher": "Google LLC", "version": "157.0.8103.78", "deviceCount": 3},
    {"displayName": "Remote Desktop Agent Boot Loader", "publisher": "Microsoft Corporation", "version": "1.0.1", "deviceCount": 1},
    {"displayName": "Remote Desktop Agent Boot Loader", "publisher": "Microsoft Corporation", "version": "1.0.2", "deviceCount": 1},
    {"displayName": "Microsoft.Paint", "publisher": "CN=Microsoft Corporation, O=Microsoft", "version": "11.1.0.0", "deviceCount": 5},
]


class VendorVersionTests(unittest.TestCase):
    def run_check(self, **kwargs):
        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
                return await vv.check_vendor_versions(APPS, http=http, **kwargs)
        return asyncio.run(go())

    def test_edge_uses_stable_windows_x64_and_counts_devices_behind(self):
        edge = next(row for row in self.run_check()["apps"] if row["app"] == "Microsoft Edge")
        self.assertEqual(edge["vendorLatest"], "157.0.4341.60")
        self.assertEqual(edge["devicesBehind"], 10)
        self.assertEqual([row["status"] for row in edge["installed"]], ["current", "outdated"])

    def test_m365_build_on_another_supported_channel_is_not_called_outdated(self):
        m365 = next(row for row in self.run_check()["apps"] if row["app"].startswith("Microsoft 365"))
        self.assertEqual(m365["vendorLatest"], "16.0.20527.20196")
        self.assertEqual(m365["devicesBehind"], 2)

    def test_git_tag_with_windows_suffix_compares_numerically(self):
        git = next(row for row in self.run_check()["apps"] if row["app"] == "Git")
        self.assertEqual((git["status"], git["devicesBehind"]), ("outdated", 2))

    def test_unreachable_vendor_and_unregistered_apps_are_reported_not_guessed(self):
        result = self.run_check()
        reasons = {row["app"]: row["reason"] for row in result["notChecked"]}
        self.assertIn("unreachable", reasons["Google Chrome"])
        self.assertIn("Microsoft service", reasons["Remote Desktop Agent Boot Loader"])
        self.assertNotIn("Google Chrome", [row["app"] for row in result["apps"]])

    def test_store_packages_are_not_treated_as_win32(self):
        names = [row["app"] for row in self.run_check()["apps"]] + [row["app"] for row in self.run_check()["notChecked"]]
        self.assertNotIn("Microsoft.Paint", names)

    def test_search_term_narrows_the_check(self):
        result = self.run_check(search_term="edge")
        self.assertEqual([row["app"] for row in result["apps"]], ["Microsoft Edge"])

    def test_apps_without_an_official_feed_fall_back_to_the_community_index_and_say_so(self):
        class Index:
            def latest_version(self, name):
                return {"id": "Contoso.Tool", "name": name, "version": "3.0"} if name == "Contoso Tool" else None

        apps = [{"displayName": "Contoso Tool", "publisher": "Contoso", "version": "2.0", "deviceCount": 4},
                {"displayName": "Contoso Tool", "publisher": "Contoso", "version": "3.0", "deviceCount": 1},
                {"displayName": "Mystery App", "publisher": "Nobody", "version": "1.0", "deviceCount": 1},
                {"displayName": "Mystery App", "publisher": "Nobody", "version": "2.0", "deviceCount": 1}]

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
                return await vv.check_vendor_versions(apps, http=http, index=Index())
        result = asyncio.run(go())
        tool = next(row for row in result["apps"] if row["app"] == "Contoso Tool")
        self.assertEqual((tool["confidence"], tool["vendorLatest"], tool["devicesBehind"]), ("community", "3.0", 4))
        self.assertIn("community", tool["vendorSource"])
        self.assertEqual([row["app"] for row in result["notChecked"]], ["Mystery App"])

    def test_vendor_feeds_are_marked_as_vendor_confidence(self):
        edge = next(row for row in self.run_check()["apps"] if row["app"] == "Microsoft Edge")
        self.assertEqual(edge["confidence"], "vendor")

    def test_version_compare_ignores_non_numeric_prefixes_and_suffixes(self):
        self.assertEqual(vv.compare("2.55.0", "v2.56.1.windows.1"), -1)
        self.assertEqual(vv.compare("8.9.9", "8.9.9.0"), 0)
        self.assertEqual(vv.compare("157.1", "157.0.9"), 1)


if __name__ == "__main__":
    unittest.main()
