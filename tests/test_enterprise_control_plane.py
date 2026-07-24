from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from enterprise import AuthenticationError, AuthorizationError, ConflictError, ControlPlane
from organization import OrganizationService


class EnterpriseControlPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "control-plane.db"
        organization = OrganizationService(self.database)
        self.org = organization.create_organization("Acme", "acme")
        self.department = organization.create_department(self.org["id"], "Engineering", "ENG")
        self.admin = organization.create_user(self.org["id"], "admin@acme.test", "Admin")
        self.worker = organization.create_user(self.org["id"], "worker@acme.test", "Worker", "ai")
        role = organization.create_role(self.org["id"], "Workflow Administrator")
        for permission in ("role.manage", "duty.manage", "user.manage"):
            organization.grant_permission(role["id"], permission)
        organization.assign_role(self.admin["id"], role["id"])
        worker_role = organization.create_role(self.org["id"], "Workflow Worker")
        organization.grant_permission(worker_role["id"], "duty.manage")
        organization.assign_role(self.worker["id"], worker_role["id"])
        self.control = ControlPlane(self.database)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_credentials_are_scoped_hashed_and_revocable_by_invalid_secret(self) -> None:
        credential = self.control.create_api_credential(
            self.org["id"], self.admin["id"], "admin-api", ["identity:read", "workflow:*"]
        )
        principal = self.control.authenticate(credential["token"], "workflow:write")
        self.assertEqual(principal["user_id"], self.admin["id"])
        with self.assertRaises(AuthorizationError):
            self.control.authenticate(credential["token"], "billing:write")
        prefix = credential["token"].split(".", 1)[0]
        with self.assertRaises(AuthenticationError):
            self.control.authenticate(prefix + ".wrong-secret")

    def test_deny_policy_overrides_role_permission(self) -> None:
        self.control.create_policy_rule(
            self.org["id"], self.admin["id"], "allow-workflows", "allow",
            "duty.manage", "workflow*", {}, 100,
        )
        self.assertTrue(self.control.authorize(
            self.org["id"], self.admin["id"], "duty.manage", "workflow_definition"
        ))
        self.control.create_policy_rule(
            self.org["id"], self.admin["id"], "deny-ai-approval", "deny",
            "duty.manage", "workflow_approval", {"user_type": "ai"}, 10,
        )
        self.assertFalse(self.control.authorize(
            self.org["id"], self.worker["id"], "duty.manage", "workflow_approval"
        ))

    def test_idempotent_approval_workflow_leases_and_completion(self) -> None:
        definition = self.control.create_workflow_definition(
            self.org["id"], self.admin["id"], "Release", "Controlled release",
            [
                {"key": "build", "name": "Build", "handler": "build.release", "required_permission": "duty.manage"},
                {"key": "deploy", "name": "Deploy", "handler": "deploy.release", "required_permission": "duty.manage", "depends_on": ["build"]},
            ],
            department_id=self.department["id"], approval_required=True,
        )
        self.control.activate_workflow_definition(self.org["id"], self.admin["id"], definition["id"])
        first = self.control.start_workflow(
            self.org["id"], self.admin["id"], definition["id"], "release-42", {"sha": "abc123"}
        )
        repeated = self.control.start_workflow(
            self.org["id"], self.admin["id"], definition["id"], "release-42", {"sha": "different"}
        )
        self.assertEqual(first["id"], repeated["id"])
        self.assertEqual(first["state"], "awaiting_approval")
        self.control.approve_workflow(self.org["id"], first["id"], self.admin["id"])

        build = self.control.lease_next_step(self.org["id"], "worker-1")
        self.assertEqual(build["step_key"], "build")
        self.control.begin_step(build["id"], "worker-1", build["lease_token"])
        self.control.complete_step(build["id"], "worker-1", build["lease_token"], {"artifact": "release.zip"})

        deploy = self.control.lease_next_step(self.org["id"], "worker-1")
        self.assertEqual(deploy["step_key"], "deploy")
        self.control.begin_step(deploy["id"], "worker-1", deploy["lease_token"])
        self.control.complete_step(deploy["id"], "worker-1", deploy["lease_token"], {"url": "https://example.test"})

        snapshot = self.control.get_workflow_run(self.org["id"], self.admin["id"], first["id"])
        self.assertEqual(snapshot["run"]["state"], "succeeded")
        self.assertEqual([step["state"] for step in snapshot["steps"]], ["succeeded", "succeeded"])
        self.assertGreaterEqual(len(snapshot["events"]), 4)

    def test_retry_and_dead_letter_after_attempt_budget(self) -> None:
        definition = self.control.create_workflow_definition(
            self.org["id"], self.admin["id"], "Fragile", "Retry test",
            [{"key": "send", "name": "Send", "handler": "send.message", "required_permission": "duty.manage", "max_attempts": 1}],
        )
        self.control.activate_workflow_definition(self.org["id"], self.admin["id"], definition["id"])
        run = self.control.start_workflow(
            self.org["id"], self.admin["id"], definition["id"], "fragile-1", {}
        )
        lease = self.control.lease_next_step(self.org["id"], "worker-2")
        self.control.begin_step(lease["id"], "worker-2", lease["lease_token"])
        state = self.control.fail_step(
            lease["id"], "worker-2", lease["lease_token"], {"code": "timeout"}, True
        )
        self.assertEqual(state, "dead_letter")
        snapshot = self.control.get_workflow_run(self.org["id"], self.admin["id"], run["id"])
        self.assertEqual(snapshot["run"]["state"], "dead_letter")

    def test_invalid_or_reused_lease_is_rejected(self) -> None:
        definition = self.control.create_workflow_definition(
            self.org["id"], self.admin["id"], "Single", "Lease test",
            [{"key": "one", "name": "One", "handler": "one", "required_permission": "duty.manage"}],
        )
        self.control.activate_workflow_definition(self.org["id"], self.admin["id"], definition["id"])
        self.control.start_workflow(self.org["id"], self.admin["id"], definition["id"], "single-1", {})
        lease = self.control.lease_next_step(self.org["id"], "worker-3")
        with self.assertRaises(ConflictError):
            self.control.begin_step(lease["id"], "worker-3", "wrong-token")


if __name__ == "__main__":
    unittest.main()
