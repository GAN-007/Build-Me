from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from production import (
    BillingService,
    EntitlementDenied,
    IdentityService,
    InvalidSession,
    QuotaExceeded,
    RecoveryService,
    RestoreVerificationError,
)


def iso(days: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


class BillingServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "platform.sqlite3"
        self.billing = BillingService(self.database)
        self.organization_id = "org-1"
        self.plan = self.billing.create_plan(
            code="scale",
            name="Scale",
            currency="KES",
            recurring_amount_minor=1250000,
            billing_interval="month",
            entitlements={
                "workflow.execute": {"enabled": True, "quota_limit": 3, "quota_period": "month"},
                "audit.export": {"enabled": False},
            },
        )
        self.subscription = self.billing.create_subscription(
            self.organization_id,
            self.plan["id"],
            iso(-1),
            iso(30),
            provider="manual",
            provider_subscription_id="sub-1",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_money_is_minor_units_only(self) -> None:
        with self.assertRaises(ValueError):
            self.billing.create_plan("bad", "Bad", "USD", "12.50", "month", {})

    def test_usage_is_idempotent(self) -> None:
        first = self.billing.record_usage(self.organization_id, "evt-1", "workflow_runs", 2)
        second = self.billing.record_usage(self.organization_id, "evt-1", "workflow_runs", 2)
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["id"], second["id"])

    def test_entitlement_and_quota_enforcement(self) -> None:
        self.billing.record_usage(self.organization_id, "evt-1", "workflow_runs", 2)
        resolved = self.billing.require_entitlement(
            self.organization_id,
            "workflow.execute",
            meter_key="workflow_runs",
            requested_quantity=1,
            period_start=iso(-2),
            period_end=iso(31),
        )
        self.assertEqual(resolved["remaining"], 1)
        with self.assertRaises(QuotaExceeded):
            self.billing.require_entitlement(
                self.organization_id,
                "workflow.execute",
                meter_key="workflow_runs",
                requested_quantity=2,
                period_start=iso(-2),
                period_end=iso(31),
            )
        with self.assertRaises(EntitlementDenied):
            self.billing.require_entitlement(self.organization_id, "audit.export")

    def test_override_takes_precedence(self) -> None:
        self.billing.set_override(self.organization_id, "audit.export", True, "contract amendment")
        self.assertEqual(self.billing.resolve_entitlement(self.organization_id, "audit.export")["source"], "override")


class IdentityServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "identity.sqlite3"
        self.identity = IdentityService(self.database)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_session_secret_is_not_stored(self) -> None:
        session = self.identity.create_session("org-1", "user-1", "oidc", 2)
        with sqlite3.connect(self.database) as db:
            row = db.execute("SELECT token_prefix, token_hash FROM identity_sessions WHERE id=?", (session["session_id"],)).fetchone()
        self.assertNotEqual(row[0], session["token"])
        self.assertNotIn(session["token"].encode(), row[1])
        principal = self.identity.authenticate(session["token"], required_assurance=2)
        self.assertEqual(principal["user_id"], "user-1")

    def test_assurance_and_revocation(self) -> None:
        session = self.identity.create_session("org-1", "user-1", "passwordless", 1)
        with self.assertRaises(InvalidSession):
            self.identity.authenticate(session["token"], required_assurance=2)
        self.identity.revoke_session(session["session_id"], "user logout")
        with self.assertRaises(InvalidSession):
            self.identity.authenticate(session["token"])

    def test_rotation_revokes_old_token(self) -> None:
        first = self.identity.create_session("org-1", "user-1", "oidc", 2)
        second = self.identity.rotate_session(first["token"])
        with self.assertRaises(InvalidSession):
            self.identity.authenticate(first["token"])
        self.assertEqual(self.identity.authenticate(second["token"])["user_id"], "user-1")


class RecoveryServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.database = root / "source.sqlite3"
        self.backups = root / "backups"
        with sqlite3.connect(self.database) as db:
            db.execute("CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
            db.executemany("INSERT INTO records(value) VALUES(?)", [("one",), ("two",)])
        self.recovery = RecoveryService(self.database, self.backups)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_backup_and_restore_drill(self) -> None:
        manifest = self.recovery.create_backup()
        verified = self.recovery.verify_backup(manifest["backup_id"])
        drill = self.recovery.restore_drill(manifest["backup_id"])
        self.assertTrue(verified["verified"])
        self.assertEqual(drill["table_counts"]["records"], 2)

    def test_tampering_is_detected(self) -> None:
        manifest = self.recovery.create_backup()
        database = self.backups / manifest["database_file"]
        database.write_bytes(database.read_bytes() + b"tamper")
        with self.assertRaises(RestoreVerificationError):
            self.recovery.verify_backup(manifest["backup_id"])

    def test_restore_refuses_overwrite_without_flag(self) -> None:
        manifest = self.recovery.create_backup()
        destination = Path(self.temp.name) / "existing.sqlite3"
        destination.write_text("occupied", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            self.recovery.restore_to(manifest["backup_id"], destination)


if __name__ == "__main__":
    unittest.main()
