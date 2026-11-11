import unittest
from unittest.mock import patch

from intune_mcp_server import server


class FakeGraphClient:
    def __init__(self):
        self.posts = []

    async def post(self, endpoint, **kwargs):
        self.posts.append((endpoint, kwargs))
        return {"status": "ok"}


class ManageIntuneScriptsAssignmentTests(unittest.IsolatedAsyncioTestCase):
    async def test_powershell_script_assigns_to_security_group(self):
        client = FakeGraphClient()
        with patch.object(server, "get_graph_client", return_value=client):
            result = await server.manage_intune_scripts(
                action="assign",
                script_id="script-1",
                group_id="group-1",
                confirm=True,
            )

        self.assertEqual(result, {"status": "ok"})
        endpoint, options = client.posts[0]
        self.assertEqual(
            endpoint,
            "/deviceManagement/deviceManagementScripts/script-1/assign",
        )
        self.assertTrue(options["use_beta"])
        self.assertEqual(
            options["json"],
            {
                "deviceManagementScriptGroupAssignments": [
                    {
                        "@odata.type": "#microsoft.graph.deviceManagementScriptGroupAssignment",
                        "targetGroupId": "group-1",
                    }
                ]
            },
        )

    async def test_remediation_assignment_uses_group_target_and_run_flag(self):
        client = FakeGraphClient()
        with patch.object(server, "get_graph_client", return_value=client):
            await server.manage_intune_scripts(
                action="assign",
                script_id="health-script-1",
                script_type="remediation",
                group_id="group-2",
                run_remediation_script=True,
                confirm=True,
            )

        endpoint, options = client.posts[0]
        self.assertEqual(
            endpoint,
            "/deviceManagement/deviceHealthScripts/health-script-1/assign",
        )
        self.assertEqual(
            options["json"],
            {
                "deviceHealthScriptAssignments": [
                    {
                        "@odata.type": "#microsoft.graph.deviceHealthScriptAssignment",
                        "target": {
                            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                            "groupId": "group-2",
                        },
                        "runRemediationScript": True,
                    }
                ]
            },
        )

    async def test_assignment_requires_explicit_confirmation(self):
        client = FakeGraphClient()
        with patch.object(server, "get_graph_client", return_value=client):
            result = await server.manage_intune_scripts(
                action="assign",
                script_id="script-1",
                group_id="group-1",
            )

        self.assertEqual(result["status"], "confirmation_required")
        self.assertEqual(client.posts, [])

    async def test_advanced_body_uses_assign_action(self):
        client = FakeGraphClient()
        assignment_body = {"deviceManagementScriptAssignments": []}
        with patch.object(server, "get_graph_client", return_value=client):
            await server.manage_intune_scripts(
                action="assign",
                script_id="script-1",
                body=assignment_body,
                confirm=True,
            )

        endpoint, options = client.posts[0]
        self.assertEqual(
            endpoint,
            "/deviceManagement/deviceManagementScripts/script-1/assign",
        )
        self.assertIs(options["json"], assignment_body)

    async def test_group_id_and_advanced_body_cannot_be_combined(self):
        client = FakeGraphClient()
        with patch.object(server, "get_graph_client", return_value=client):
            result = await server.manage_intune_scripts(
                action="assign",
                script_id="script-1",
                group_id="group-1",
                body={"deviceManagementScriptAssignments": []},
                confirm=True,
            )

        self.assertIn("either group_id or body", result["error"])
        self.assertEqual(client.posts, [])


if __name__ == "__main__":
    unittest.main()
