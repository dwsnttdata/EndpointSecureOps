import asyncio
import io
import unittest
import zipfile
from types import SimpleNamespace

import httpx

from intune_mcp_server import app_management as am

APP = "11111111-2222-3333-4444-555555555555"
OLD = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GROUP = "5b1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8"


def run(coro):
    return asyncio.run(coro)


class Graph:
    """Scripted Graph: routes by substring, records every call."""

    config = SimpleNamespace(beta_endpoint="https://graph.microsoft.com/beta", graph_endpoint="https://graph.microsoft.com/v1.0")

    def __init__(self, routes=None):
        self.routes, self.calls = routes or {}, []

    async def get(self, endpoint, **kwargs):
        self.calls.append(("GET", endpoint, None))
        for fragment, response in self.routes.items():
            if fragment in endpoint:
                return response(endpoint) if callable(response) else response
        return {"value": []}

    async def post(self, endpoint, **kwargs):
        self.calls.append(("POST", endpoint, kwargs.get("json")))
        for fragment, response in self.routes.items():
            if fragment in endpoint:
                return response(endpoint) if callable(response) else response
        return {}


class SearchTests(unittest.TestCase):
    def test_search_is_case_insensitive_and_matches_publisher(self):
        apps = [{"id": "1", "displayName": "VLC media player", "publisher": "VideoLAN"}, {"id": "2", "displayName": "Other", "publisher": "Acme"}]
        graph = Graph({"$search": {"value": apps}})
        self.assertEqual([a["id"] for a in run(am.search_apps(graph, "vlc"))["apps"]], ["1"])
        self.assertEqual([a["id"] for a in run(am.search_apps(graph, "VIDEOLAN"))["apps"]], ["1"])
        self.assertNotIn("$count", graph.calls[0][1])

    def test_search_falls_back_to_a_full_scan_when_search_returns_nothing(self):
        graph = Graph({"$search": {"value": []}, "mobileApps?$top=100": {"value": [{"id": "9", "displayName": "AnyDesk", "publisher": "x"}]}})
        self.assertEqual([a["id"] for a in run(am.search_apps(graph, "anydesk"))["apps"]], ["9"])

    def test_search_sends_graph_only_a_plain_word_so_plus_signs_work(self):
        graph = Graph({"$search": {"value": [{"id": "1", "displayName": "Notepad++ (x64)", "publisher": "Don Ho"}, {"id": "2", "displayName": "Notepad Pro", "publisher": "x"}]}})
        result = run(am.search_apps(graph, "Notepad++"))
        self.assertEqual([app["id"] for app in result["apps"]], ["1"])
        self.assertIn("%22Notepad%22", graph.calls[0][1])
        self.assertNotIn("%2B", graph.calls[0][1])

    def test_list_filters_by_real_type_on_beta(self):
        graph = Graph({"mobileApps": {"value": [{"id": "1", "@odata.type": "#microsoft.graph.win32CatalogApp", "displayName": "A"}]}})
        result = run(am.list_apps(graph, 10, "win32CatalogApp"))
        self.assertEqual(result["apps"][0]["type"], "win32CatalogApp")
        self.assertIn("isof(", graph.calls[0][1].replace("%28", "(").replace("%27", "'"))
        with self.assertRaises(am.AppManagementError):
            run(am.list_apps(graph, 10, "x') or ('1"))


class InstallStatusTests(unittest.TestCase):
    def test_overview_maps_report_columns(self):
        report = {"Schema": [{"Column": "InstalledDeviceCount"}, {"Column": "FailedDeviceCount"}, {"Column": "InstalledUserCount"}],
                  "Values": [[4, 1, 3]], "LastUpdatedTime": "t"}
        result = run(am.install_overview(Graph({"getAppStatusOverviewReport": report}), APP))
        self.assertEqual((result["devices"]["installed"], result["devices"]["failed"], result["users"]["installed"]), (4, 1, 3))

    def test_devices_use_the_export_job_and_readable_state(self):
        csv_text = "DeviceName,UserPrincipalName,Platform,AppVersion,InstallState,AppInstallState_loc,HexErrorCode,LastModifiedDateTime\nPC1,a@b.c,Windows,1.0,3,Not installed,,2026-11-17 13:46:36.1\n"
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("report.csv", csv_text)
        graph = Graph({"exportJobs('": {"status": "completed", "url": "https://store.blob.core.windows.net/x?sig=SECRET"}, "exportJobs": {"id": "Job_1"}})
        http = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=buffer.getvalue())))

        async def go():
            async with http:
                return await am.install_devices(graph, APP, http=http, delay=0)
        rows = run(go())
        self.assertEqual((rows[0]["deviceName"], rows[0]["state"], rows[0]["lastModified"]), ("PC1", "Not installed", "2026-11-17 13:46:36"))

    def test_report_download_must_be_azure_blob_https(self):
        graph = Graph({"exportJobs('": {"status": "completed", "url": "https://evil.example/report.zip"}, "exportJobs": {"id": "Job_1"}})
        with self.assertRaises(am.AppManagementError):
            run(am.install_devices(graph, APP, delay=0))

    def test_app_id_must_be_a_guid(self):
        with self.assertRaises(am.AppManagementError):
            run(am.install_overview(Graph(), "x' or '1'='1"))


class AssignmentTests(unittest.TestCase):
    def graph(self, existing, app_type="#microsoft.graph.win32LobApp"):
        return Graph({f"mobileApps/{APP}/assignments": {"value": existing}, f"mobileApps/{APP}": {"id": APP, "displayName": "App", "@odata.type": app_type},
                      "/groups?$filter": {"value": [{"id": GROUP, "displayName": "Pilot Group"}]}, f"/groups/{GROUP}": {"id": GROUP, "displayName": "Pilot Group"}})

    def test_add_keeps_other_assignments_and_replace_drops_them(self):
        other = {"id": "x", "intent": "required", "target": {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": "other-group"}}
        plan = run(am.plan_assignment(self.graph([other]), APP, "Pilot Group", "required", mode="add"))
        self.assertEqual(len(plan["assignments"]), 2)
        self.assertEqual(plan["removes"], [])
        plan = run(am.plan_assignment(self.graph([other]), APP, "Pilot Group", "required", mode="replace"))
        self.assertEqual(len(plan["assignments"]), 1)
        self.assertEqual(len(plan["removes"]), 1)

    def test_same_group_changes_intent_instead_of_duplicating(self):
        existing = {"id": "x", "intent": "required", "target": {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": GROUP}}
        plan = run(am.plan_assignment(self.graph([existing]), APP, GROUP, "uninstall"))
        self.assertEqual([item["intent"] for item in plan["assignments"]], ["uninstall"])

    def test_catalog_apps_never_get_win32_settings_and_reject_notifications(self):
        catalog = self.graph([], "#microsoft.graph.win32CatalogApp")
        plan = run(am.plan_assignment(catalog, APP, GROUP, "required"))
        self.assertNotIn("settings", plan["assignments"][0])
        with self.assertRaises(am.AppManagementError):
            run(am.plan_assignment(catalog, APP, GROUP, "required", notifications="hideAll"))

    def test_win32_apps_carry_notification_settings(self):
        plan = run(am.plan_assignment(self.graph([]), APP, GROUP, "required", notifications="hideAll"))
        self.assertEqual(plan["assignments"][0]["settings"]["notifications"], "hideAll")

    def test_all_users_requires_naming_it_and_is_flagged_broad(self):
        plan = run(am.plan_assignment(self.graph([]), APP, "All users", "available"))
        self.assertTrue(plan["broad"])
        self.assertEqual(plan["assignments"][0]["target"]["@odata.type"], "#microsoft.graph.allLicensedUsersAssignmentTarget")
        with self.assertRaises(am.AppManagementError):
            run(am.plan_assignment(self.graph([]), APP, "All users", "available", exclude=True))

    def test_unknown_or_ambiguous_group_is_an_error_not_a_guess(self):
        empty = Graph({f"mobileApps/{APP}": {"id": APP, "@odata.type": "x"}, "/groups?$filter": {"value": []}})
        with self.assertRaises(am.AppManagementError):
            run(am.plan_assignment(empty, APP, "Nope", "required"))
        two = Graph({f"mobileApps/{APP}": {"id": APP, "@odata.type": "x"}, "/groups?$filter": {"value": [{"id": "1", "displayName": "T"}, {"id": "2", "displayName": "T"}]}})
        with self.assertRaises(am.AppManagementError):
            run(am.plan_assignment(two, APP, "T", "required"))

    def test_bad_intent_and_group_names_with_quotes_are_handled(self):
        with self.assertRaises(am.AppManagementError):
            am.build_assignment("deploy", {"id": GROUP, "broad": None}, "x")
        graph = self.graph([])
        run(am.plan_assignment(graph, APP, "O'Brien team", "required"))
        self.assertIn("O%27%27Brien", next(call[1] for call in graph.calls if "/groups?$filter" in call[1]))


class RelationshipTests(unittest.TestCase):
    def test_set_relationships_merges_existing_children(self):
        existing = {"value": [{"@odata.type": "#microsoft.graph.mobileAppDependency", "targetId": OLD, "dependencyType": "detect", "targetType": "child", "id": "r1"},
                              {"@odata.type": "#microsoft.graph.mobileAppSupersedence", "targetId": "parent", "targetType": "parent"}]}
        graph = Graph({"/relationships": existing})
        run(am.set_relationships(graph, APP, [am.supersedence(OLD, "update")]))
        posted = next(call for call in graph.calls if call[0] == "POST")[2]["relationships"]
        self.assertEqual(sorted(item["@odata.type"].rsplit(".", 1)[-1] for item in posted), ["mobileAppDependency", "mobileAppSupersedence"])
        self.assertNotIn("parent", [item["targetId"] for item in posted])

    def test_relationship_inputs_are_validated(self):
        with self.assertRaises(am.AppManagementError):
            am.supersedence("not-a-guid")
        with self.assertRaises(am.AppManagementError):
            am.supersedence(OLD, "delete")
        with self.assertRaises(am.AppManagementError):
            am.dependency(OLD, "x")


class CatalogUpdateTests(unittest.TestCase):
    def graph(self, catalog_rows, app_version="8.8.1"):
        app = {"id": OLD, "displayName": "Notepad++", "displayVersion": app_version, "@odata.type": "#microsoft.graph.win32CatalogApp",
               "mobileAppCatalogPackageId": "pkg-old", "isAssigned": True}
        package = {"id": "pkg-old", "productId": "prod", "branchId": "branch", "productDisplayName": "Notepad++", "versionDisplayName": app_version}

        def packages(endpoint):
            return {"value": catalog_rows} if "$search" in endpoint else package
        return Graph({"isof(": {"value": [app]}, "mobileAppCatalogPackages": packages, f"mobileApps/{OLD}/assignments": {"value": [
            {"id": "z", "intent": "required", "target": {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": GROUP}, "settings": {"@odata.type": "w"}}]},
            f"mobileApps/{OLD}": app, "/groups/": {"displayName": "G"}})

    def test_branch_is_matched_by_id_so_renamed_branches_still_update(self):
        rows = [{"id": "pkg-new", "productId": "prod", "branchId": "branch", "versionDisplayName": "8.9.9.1", "branchDisplayName": "Renamed (exe)"},
                {"id": "other", "productId": "other", "branchId": "branch", "versionDisplayName": "99.0"}]
        result = run(am.check_catalog_updates(self.graph(rows)))
        self.assertEqual((result["updatesAvailable"], result["apps"][0]["catalogVersion"], result["apps"][0]["newPackageId"]), (1, "8.9.9.1", "pkg-new"))

    def test_missing_branch_is_reported_as_retired_with_candidates(self):
        graph = self.graph([{"id": "c1", "productId": "different", "branchId": "b2", "productDisplayName": "Notepad++", "versionDisplayName": "9", "branchDisplayName": "x"}])
        result = run(am.check_catalog_updates(graph))
        self.assertEqual((result["updatesAvailable"], len(result["retired"])), (0, 1))
        self.assertEqual(result["retired"][0]["replacementCandidates"][0]["packageId"], "c1")

    def test_update_plan_copies_assignments_without_win32_settings(self):
        rows = [{"id": "pkg-new", "productId": "prod", "branchId": "branch", "versionDisplayName": "8.9.9.1", "branchDisplayName": "b"}]
        plan = run(am.plan_catalog_update(self.graph(rows), OLD))
        self.assertEqual((plan["status"], plan["newPackage"]["id"]), ("update_available", "pkg-new"))
        self.assertNotIn("settings", plan["assignments"][0])
        self.assertNotIn("id", plan["assignments"][0])

    def test_update_plan_can_target_a_chosen_group(self):
        rows = [{"id": "pkg-new", "productId": "prod", "branchId": "branch", "versionDisplayName": "9.0", "branchDisplayName": "b"}]
        graph = self.graph(rows)
        graph.routes = {f"/groups/{GROUP}": {"id": GROUP, "displayName": "Test"}, **graph.routes}
        plan = run(am.plan_catalog_update(graph, OLD, GROUP))
        self.assertEqual(plan["assignments"][0]["target"]["groupId"], GROUP)

    def test_up_to_date_and_non_catalog_apps_are_not_updated(self):
        rows = [{"id": "pkg-same", "productId": "prod", "branchId": "branch", "versionDisplayName": "8.8.1", "branchDisplayName": "b"}]
        self.assertEqual(run(am.plan_catalog_update(self.graph(rows), OLD))["status"], "up_to_date")
        plain = Graph({f"mobileApps/{OLD}": {"id": OLD, "@odata.type": "#microsoft.graph.win32LobApp"}})
        with self.assertRaises(am.AppManagementError):
            run(am.plan_catalog_update(plain, OLD))


if __name__ == "__main__":
    unittest.main()
