import tempfile
import unittest
from pathlib import Path

from organization import OrganizationService, PermissionDenied, ValidationError


class OrganizationServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.service = OrganizationService(Path(self.tempdir.name) / "organization.db")
        self.organization = self.service.create_organization("Build Me", "build-me")
        self.department = self.service.create_department(
            self.organization["id"], "Engineering", "ENG", "Build and operate products"
        )
        self.admin = self.service.create_user(
            self.organization["id"], "admin@example.com", "Admin"
        )
        self.role = self.service.create_role(
            self.organization["id"], "Department Administrator", self.department["id"]
        )
        for permission in ("department.manage", "user.manage", "role.manage", "duty.manage", "kpi.manage", "audit.read"):
            self.service.grant_permission(self.role["id"], permission)
        self.service.assign_role(self.admin["id"], self.role["id"])

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_department_user_role_and_permission_are_scoped(self) -> None:
        self.assertTrue(
            self.service.has_permission(self.admin["id"], self.organization["id"], "duty.manage")
        )
        other = self.service.create_organization("Other", "other")
        self.assertFalse(self.service.has_permission(self.admin["id"], other["id"], "duty.manage"))

    def test_dynamic_duty_and_kpi_lifecycle(self) -> None:
        duty = self.service.create_duty(
            self.organization["id"], self.department["id"], "Review incidents",
            "Review production incidents and assign corrective actions", "weekly", "high",
            self.admin["id"], {"sla_hours": 24}, self.admin["id"]
        )
        kpi = self.service.create_kpi(
            self.organization["id"], self.department["id"], "Deployment success rate",
            "percent", "increase", 99.5, "monthly", self.admin["id"], self.admin["id"]
        )
        updated = self.service.update_kpi_value(kpi["id"], 99.7, self.admin["id"])
        snapshot = self.service.organization_snapshot(self.organization["id"])
        self.assertEqual(duty["metadata"]["sla_hours"], 24)
        self.assertEqual(updated["current_value"], 99.7)
        self.assertEqual(snapshot["counts"]["duties"], 1)
        self.assertEqual(snapshot["counts"]["kpis"], 1)

    def test_unprivileged_user_cannot_manage_kpis(self) -> None:
        viewer = self.service.create_user(self.organization["id"], "viewer@example.com", "Viewer")
        with self.assertRaises(PermissionDenied):
            self.service.create_kpi(
                self.organization["id"], self.department["id"], "Availability", "percent",
                "increase", 99.9, "monthly", actor_user_id=viewer["id"]
            )

    def test_audit_log_requires_permission_and_records_mutations(self) -> None:
        events = self.service.audit_events(self.organization["id"], self.admin["id"])
        actions = {event["action"] for event in events}
        self.assertIn("organization.created", actions)
        self.assertIn("role.assigned", actions)
        outsider = self.service.create_user(self.organization["id"], "outsider@example.com", "Outsider")
        with self.assertRaises(PermissionDenied):
            self.service.audit_events(self.organization["id"], outsider["id"])

    def test_validation_rejects_invalid_slug_and_priority(self) -> None:
        with self.assertRaises(ValidationError):
            self.service.create_organization("Invalid", "invalid slug")
        with self.assertRaises(ValidationError):
            self.service.create_duty(
                self.organization["id"], self.department["id"], "Bad", "Bad priority",
                "daily", "urgent", actor_user_id=self.admin["id"]
            )


if __name__ == "__main__":
    unittest.main()
