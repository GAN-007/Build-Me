from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterator


class EntitlementDenied(RuntimeError):
    pass


class QuotaExceeded(RuntimeError):
    pass


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id() -> str:
    return str(uuid.uuid4())


def _minor_units(value: int | str | Decimal) -> int:
    if isinstance(value, int):
        return value
    try:
        parsed = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("invalid monetary amount") from exc
    if parsed != parsed.to_integral_value():
        raise ValueError("amount must be supplied in integer minor units")
    return int(parsed)


class BillingService:
    """Transactional plans, subscriptions, entitlements, quotas, and immutable usage."""

    def __init__(self, database: str | Path = "data/organization.db") -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @contextmanager
    def _connection(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.database, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA busy_timeout = 30000")
        try:
            if immediate:
                db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _migrate(self) -> None:
        with self._connection() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS billing_plans (
                    id TEXT PRIMARY KEY, code TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
                    currency TEXT NOT NULL, recurring_amount_minor INTEGER NOT NULL CHECK(recurring_amount_minor>=0),
                    billing_interval TEXT NOT NULL CHECK(billing_interval IN ('month','year')),
                    status TEXT NOT NULL CHECK(status IN ('active','retired')),
                    metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS plan_entitlements (
                    plan_id TEXT NOT NULL, entitlement_key TEXT NOT NULL,
                    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), quota_limit INTEGER,
                    quota_period TEXT CHECK(quota_period IN ('day','month','year') OR quota_period IS NULL),
                    PRIMARY KEY(plan_id, entitlement_key),
                    FOREIGN KEY(plan_id) REFERENCES billing_plans(id) ON DELETE CASCADE,
                    CHECK(quota_limit IS NULL OR quota_limit>=0)
                );
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, plan_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('trialing','active','past_due','paused','cancelled','expired')),
                    period_start TEXT NOT NULL, period_end TEXT NOT NULL,
                    cancel_at_period_end INTEGER NOT NULL DEFAULT 0 CHECK(cancel_at_period_end IN (0,1)),
                    provider TEXT, provider_customer_id TEXT, provider_subscription_id TEXT,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    UNIQUE(provider, provider_subscription_id),
                    FOREIGN KEY(plan_id) REFERENCES billing_plans(id) ON DELETE RESTRICT,
                    CHECK(period_end>period_start)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS uq_active_subscription_per_org
                    ON subscriptions(organization_id) WHERE status IN ('trialing','active','past_due','paused');
                CREATE TABLE IF NOT EXISTS usage_events (
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, subscription_id TEXT,
                    event_key TEXT NOT NULL, meter_key TEXT NOT NULL,
                    quantity INTEGER NOT NULL CHECK(quantity>0), amount_minor INTEGER NOT NULL DEFAULT 0 CHECK(amount_minor>=0),
                    occurred_at TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
                    UNIQUE(organization_id,event_key),
                    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE SET NULL
                );
                CREATE INDEX IF NOT EXISTS idx_usage_meter_period ON usage_events(organization_id,meter_key,occurred_at);
                CREATE TABLE IF NOT EXISTS entitlement_overrides (
                    organization_id TEXT NOT NULL, entitlement_key TEXT NOT NULL,
                    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), quota_limit INTEGER,
                    expires_at TEXT, reason TEXT NOT NULL, created_at TEXT NOT NULL,
                    PRIMARY KEY(organization_id,entitlement_key), CHECK(quota_limit IS NULL OR quota_limit>=0)
                );
                """
            )

    def create_plan(self, code: str, name: str, currency: str, recurring_amount_minor: int | str | Decimal,
                    billing_interval: str, entitlements: dict[str, dict[str, Any]]) -> dict[str, Any]:
        code = code.strip().lower()
        currency = currency.strip().upper()
        if not code or not code.replace("-", "").isalnum():
            raise ValueError("invalid plan code")
        if not name.strip():
            raise ValueError("plan name is required")
        if billing_interval not in {"month", "year"}:
            raise ValueError("billing_interval must be month or year")
        if len(currency) != 3 or not currency.isalpha():
            raise ValueError("currency must be a three-letter code")
        now, plan_id = _utcnow(), _id()
        with self._connection(immediate=True) as db:
            db.execute("INSERT INTO billing_plans VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (plan_id, code, name.strip(), currency, _minor_units(recurring_amount_minor),
                        billing_interval, "active", "{}", now, now))
            for key, definition in sorted(entitlements.items()):
                key = key.strip()
                quota = definition.get("quota_limit")
                period = definition.get("quota_period")
                if not key:
                    raise ValueError("entitlement key is required")
                if quota is not None and int(quota) < 0:
                    raise ValueError("quota_limit must not be negative")
                if period not in {None, "day", "month", "year"}:
                    raise ValueError("invalid quota_period")
                db.execute("INSERT INTO plan_entitlements VALUES(?,?,?,?,?)",
                           (plan_id, key, int(bool(definition.get("enabled", True))), quota, period))
        return self.get_plan(plan_id)

    def get_plan(self, plan_id: str) -> dict[str, Any]:
        with self._connection() as db:
            plan = db.execute("SELECT * FROM billing_plans WHERE id=?", (plan_id,)).fetchone()
            if plan is None:
                raise KeyError("plan not found")
            entitlements = db.execute("SELECT * FROM plan_entitlements WHERE plan_id=? ORDER BY entitlement_key",
                                      (plan_id,)).fetchall()
        result = dict(plan)
        result["metadata"] = json.loads(result.pop("metadata_json"))
        result["entitlements"] = [dict(row) for row in entitlements]
        return result

    def create_subscription(self, organization_id: str, plan_id: str, period_start: str, period_end: str,
                            status: str = "active", provider: str | None = None,
                            provider_customer_id: str | None = None,
                            provider_subscription_id: str | None = None) -> dict[str, Any]:
        if status not in {"trialing", "active", "past_due", "paused", "cancelled", "expired"}:
            raise ValueError("invalid subscription status")
        if period_end <= period_start:
            raise ValueError("period_end must be after period_start")
        now, subscription_id = _utcnow(), _id()
        with self._connection(immediate=True) as db:
            if db.execute("SELECT 1 FROM billing_plans WHERE id=? AND status='active'", (plan_id,)).fetchone() is None:
                raise KeyError("active plan not found")
            db.execute("INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (subscription_id, organization_id, plan_id, status, period_start, period_end, 0,
                        provider, provider_customer_id, provider_subscription_id, now, now))
            row = db.execute("SELECT * FROM subscriptions WHERE id=?", (subscription_id,)).fetchone()
        return dict(row)

    def set_override(self, organization_id: str, entitlement_key: str, enabled: bool, reason: str,
                     quota_limit: int | None = None, expires_at: str | None = None) -> None:
        if quota_limit is not None and quota_limit < 0:
            raise ValueError("quota_limit must not be negative")
        if not reason.strip():
            raise ValueError("override reason is required")
        with self._connection(immediate=True) as db:
            db.execute(
                """INSERT INTO entitlement_overrides VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(organization_id,entitlement_key) DO UPDATE SET
                   enabled=excluded.enabled, quota_limit=excluded.quota_limit,
                   expires_at=excluded.expires_at, reason=excluded.reason, created_at=excluded.created_at""",
                (organization_id, entitlement_key.strip(), int(enabled), quota_limit, expires_at, reason.strip(), _utcnow()),
            )

    def resolve_entitlement(self, organization_id: str, entitlement_key: str, at: str | None = None) -> dict[str, Any]:
        moment = at or _utcnow()
        with self._connection() as db:
            override = db.execute(
                "SELECT * FROM entitlement_overrides WHERE organization_id=? AND entitlement_key=? AND (expires_at IS NULL OR expires_at>?)",
                (organization_id, entitlement_key, moment),
            ).fetchone()
            if override is not None:
                return dict(override) | {"source": "override", "quota_period": None}
            row = db.execute(
                """SELECT pe.* FROM subscriptions s JOIN plan_entitlements pe ON pe.plan_id=s.plan_id
                   WHERE s.organization_id=? AND s.status IN ('trialing','active')
                   AND s.period_start<=? AND s.period_end>? AND pe.entitlement_key=? LIMIT 1""",
                (organization_id, moment, moment, entitlement_key),
            ).fetchone()
        return (dict(row) | {"source": "plan"}) if row else {
            "enabled": 0, "quota_limit": None, "quota_period": None, "source": "none"
        }

    def record_usage(self, organization_id: str, event_key: str, meter_key: str, quantity: int = 1,
                     amount_minor: int | str | Decimal = 0, occurred_at: str | None = None,
                     metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        if quantity <= 0:
            raise ValueError("quantity must be positive")
        if not event_key.strip() or not meter_key.strip():
            raise ValueError("event_key and meter_key are required")
        timestamp = occurred_at or _utcnow()
        with self._connection(immediate=True) as db:
            existing = db.execute("SELECT * FROM usage_events WHERE organization_id=? AND event_key=?",
                                  (organization_id, event_key)).fetchone()
            if existing is not None:
                result = dict(existing)
                result["metadata"] = json.loads(result.pop("metadata_json"))
                result["idempotent"] = True
                return result
            subscription = db.execute(
                "SELECT id FROM subscriptions WHERE organization_id=? AND status IN ('trialing','active') AND period_start<=? AND period_end>? LIMIT 1",
                (organization_id, timestamp, timestamp),
            ).fetchone()
            event_id = _id()
            db.execute("INSERT INTO usage_events VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (event_id, organization_id, subscription["id"] if subscription else None,
                        event_key.strip(), meter_key.strip(), quantity, _minor_units(amount_minor), timestamp,
                        json.dumps(metadata or {}, sort_keys=True, separators=(",", ":")), _utcnow()))
            row = db.execute("SELECT * FROM usage_events WHERE id=?", (event_id,)).fetchone()
        result = dict(row)
        result["metadata"] = json.loads(result.pop("metadata_json"))
        result["idempotent"] = False
        return result

    def require_entitlement(self, organization_id: str, entitlement_key: str, meter_key: str | None = None,
                            requested_quantity: int = 1, period_start: str | None = None,
                            period_end: str | None = None) -> dict[str, Any]:
        if requested_quantity <= 0:
            raise ValueError("requested_quantity must be positive")
        resolved = self.resolve_entitlement(organization_id, entitlement_key)
        if not resolved["enabled"]:
            raise EntitlementDenied(f"entitlement required: {entitlement_key}")
        quota = resolved.get("quota_limit")
        if quota is None:
            return resolved | {"used": None, "remaining": None}
        if not meter_key or not period_start or not period_end:
            raise ValueError("meter_key and period bounds are required for quota enforcement")
        with self._connection() as db:
            used = int(db.execute(
                "SELECT COALESCE(SUM(quantity),0) used FROM usage_events WHERE organization_id=? AND meter_key=? AND occurred_at>=? AND occurred_at<?",
                (organization_id, meter_key, period_start, period_end),
            ).fetchone()["used"])
        if used + requested_quantity > int(quota):
            raise QuotaExceeded(f"quota exceeded for {entitlement_key}")
        return resolved | {"used": used, "remaining": int(quota) - used}
