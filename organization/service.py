from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


class ValidationError(ValueError):
    pass


class PermissionDenied(RuntimeError):
    pass


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id() -> str:
    return str(uuid.uuid4())


class OrganizationService:
    """Durable multi-organization control plane using SQLite.

    The service is deliberately dependency-free so the existing local runtime keeps
    working. SQLite transactions, foreign keys, unique constraints, and an append-only
    audit log provide a safe single-node foundation that can later be replaced by a
    network database without changing the domain API.
    """

    def __init__(self, database: str | Path = "data/organization.db") -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 30000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _migrate(self) -> None:
        with self._connection() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS organizations (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK(status IN ('active','suspended','archived')),
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS departments (
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
                    parent_department_id TEXT, name TEXT NOT NULL, code TEXT NOT NULL,
                    purpose TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    UNIQUE(organization_id, code),
                    FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY(parent_department_id) REFERENCES departments(id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, email TEXT NOT NULL,
                    display_name TEXT NOT NULL, user_type TEXT NOT NULL CHECK(user_type IN ('human','ai','service')),
                    status TEXT NOT NULL CHECK(status IN ('active','suspended','disabled')),
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    UNIQUE(organization_id, email),
                    FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS roles (
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, department_id TEXT,
                    name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    UNIQUE(organization_id, department_id, name),
                    FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY(department_id) REFERENCES departments(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS permissions (
                    id TEXT PRIMARY KEY, permission_key TEXT NOT NULL UNIQUE, description TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS role_permissions (
                    role_id TEXT NOT NULL, permission_id TEXT NOT NULL,
                    PRIMARY KEY(role_id, permission_id),
                    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
                    FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS user_roles (
                    user_id TEXT NOT NULL, role_id TEXT NOT NULL, assigned_at TEXT NOT NULL,
                    PRIMARY KEY(user_id, role_id),
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS duties (
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, department_id TEXT NOT NULL,
                    title TEXT NOT NULL, description TEXT NOT NULL, cadence TEXT NOT NULL,
                    priority TEXT NOT NULL CHECK(priority IN ('low','medium','high','critical')),
                    owner_user_id TEXT, status TEXT NOT NULL CHECK(status IN ('draft','active','paused','completed','cancelled')),
                    metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY(department_id) REFERENCES departments(id) ON DELETE CASCADE,
                    FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE SET NULL
                );
                CREATE TABLE IF NOT EXISTS kpis (
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, department_id TEXT NOT NULL,
                    name TEXT NOT NULL, unit TEXT NOT NULL, direction TEXT NOT NULL CHECK(direction IN ('increase','decrease','maintain')),
                    target REAL NOT NULL, current_value REAL, period TEXT NOT NULL,
                    owner_user_id TEXT, status TEXT NOT NULL CHECK(status IN ('active','paused','retired')),
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    UNIQUE(organization_id, department_id, name, period),
                    FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY(department_id) REFERENCES departments(id) ON DELETE CASCADE,
                    FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE SET NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, organization_id TEXT NOT NULL,
                    actor_user_id TEXT, action TEXT NOT NULL, entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_departments_org ON departments(organization_id);
                CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id);
                CREATE INDEX IF NOT EXISTS idx_duties_org_status ON duties(organization_id, status);
                CREATE INDEX IF NOT EXISTS idx_kpis_org_status ON kpis(organization_id, status);
                CREATE INDEX IF NOT EXISTS idx_audit_org_created ON audit_log(organization_id, created_at);
                """
            )
            defaults = {
                "organization.manage": "Create and modify organization structures",
                "department.manage": "Create and modify departments",
                "user.manage": "Create and modify workforce identities",
                "role.manage": "Create roles and permission grants",
                "duty.manage": "Create, assign, and update duties",
                "kpi.manage": "Create and update performance indicators",
                "audit.read": "Read organization audit history",
            }
            for key, description in defaults.items():
                db.execute(
                    "INSERT OR IGNORE INTO permissions(id, permission_key, description) VALUES(?,?,?)",
                    (_id(), key, description),
                )

    @staticmethod
    def _required(value: str, field: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValidationError(f"{field} is required")
        return normalized

    def _audit(self, db: sqlite3.Connection, organization_id: str, actor_user_id: str | None,
               action: str, entity_type: str, entity_id: str, payload: dict[str, Any]) -> None:
        db.execute(
            "INSERT INTO audit_log(organization_id, actor_user_id, action, entity_type, entity_id, payload_json, created_at) VALUES(?,?,?,?,?,?,?)",
            (organization_id, actor_user_id, action, entity_type, entity_id,
             json.dumps(payload, sort_keys=True, separators=(",", ":")), _utcnow()),
        )

    def create_organization(self, name: str, slug: str) -> dict[str, Any]:
        now, organization_id = _utcnow(), _id()
        clean_slug = self._required(slug, "slug").lower()
        if not clean_slug.replace("-", "").isalnum():
            raise ValidationError("slug may contain only letters, numbers, and hyphens")
        with self._connection() as db:
            db.execute("INSERT INTO organizations VALUES(?,?,?,?,?,?)",
                       (organization_id, self._required(name, "name"), clean_slug, "active", now, now))
            self._audit(db, organization_id, None, "organization.created", "organization", organization_id, {"slug": clean_slug})
        return self.get_organization(organization_id)

    def get_organization(self, organization_id: str) -> dict[str, Any]:
        with self._connection() as db:
            row = db.execute("SELECT * FROM organizations WHERE id=?", (organization_id,)).fetchone()
        if row is None:
            raise KeyError("organization not found")
        return dict(row)

    def create_department(self, organization_id: str, name: str, code: str, purpose: str = "",
                          parent_department_id: str | None = None, actor_user_id: str | None = None) -> dict[str, Any]:
        now, department_id = _utcnow(), _id()
        with self._connection() as db:
            self._assert_org(db, organization_id)
            if actor_user_id:
                self._require(db, actor_user_id, organization_id, "department.manage")
            db.execute(
                "INSERT INTO departments VALUES(?,?,?,?,?,?,?,?,?)",
                (department_id, organization_id, parent_department_id, self._required(name, "name"),
                 self._required(code, "code").upper(), purpose.strip(), "active", now, now),
            )
            self._audit(db, organization_id, actor_user_id, "department.created", "department", department_id, {"code": code.upper()})
            row = db.execute("SELECT * FROM departments WHERE id=?", (department_id,)).fetchone()
        return dict(row)

    def create_user(self, organization_id: str, email: str, display_name: str, user_type: str = "human",
                    actor_user_id: str | None = None) -> dict[str, Any]:
        if user_type not in {"human", "ai", "service"}:
            raise ValidationError("user_type must be human, ai, or service")
        now, user_id = _utcnow(), _id()
        with self._connection() as db:
            self._assert_org(db, organization_id)
            if actor_user_id:
                self._require(db, actor_user_id, organization_id, "user.manage")
            db.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?,?)",
                       (user_id, organization_id, self._required(email, "email").lower(),
                        self._required(display_name, "display_name"), user_type, "active", now, now))
            self._audit(db, organization_id, actor_user_id, "user.created", "user", user_id, {"user_type": user_type})
            row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(row)

    def create_role(self, organization_id: str, name: str, department_id: str | None = None,
                    description: str = "", actor_user_id: str | None = None) -> dict[str, Any]:
        now, role_id = _utcnow(), _id()
        with self._connection() as db:
            self._assert_org(db, organization_id)
            if actor_user_id:
                self._require(db, actor_user_id, organization_id, "role.manage")
            db.execute("INSERT INTO roles VALUES(?,?,?,?,?,?,?)",
                       (role_id, organization_id, department_id, self._required(name, "name"), description.strip(), now, now))
            self._audit(db, organization_id, actor_user_id, "role.created", "role", role_id, {"name": name})
            row = db.execute("SELECT * FROM roles WHERE id=?", (role_id,)).fetchone()
        return dict(row)

    def grant_permission(self, role_id: str, permission_key: str) -> None:
        with self._connection() as db:
            permission = db.execute("SELECT id FROM permissions WHERE permission_key=?", (permission_key,)).fetchone()
            role = db.execute("SELECT organization_id FROM roles WHERE id=?", (role_id,)).fetchone()
            if permission is None or role is None:
                raise KeyError("role or permission not found")
            db.execute("INSERT OR IGNORE INTO role_permissions VALUES(?,?)", (role_id, permission["id"]))
            self._audit(db, role["organization_id"], None, "permission.granted", "role", role_id, {"permission": permission_key})

    def assign_role(self, user_id: str, role_id: str) -> None:
        with self._connection() as db:
            pair = db.execute(
                "SELECT u.organization_id user_org, r.organization_id role_org FROM users u CROSS JOIN roles r WHERE u.id=? AND r.id=?",
                (user_id, role_id),
            ).fetchone()
            if pair is None or pair["user_org"] != pair["role_org"]:
                raise ValidationError("user and role must exist in the same organization")
            db.execute("INSERT OR IGNORE INTO user_roles VALUES(?,?,?)", (user_id, role_id, _utcnow()))
            self._audit(db, pair["user_org"], None, "role.assigned", "user", user_id, {"role_id": role_id})

    def has_permission(self, user_id: str, organization_id: str, permission_key: str) -> bool:
        with self._connection() as db:
            row = db.execute(
                """SELECT 1 FROM users u JOIN user_roles ur ON ur.user_id=u.id
                   JOIN role_permissions rp ON rp.role_id=ur.role_id
                   JOIN permissions p ON p.id=rp.permission_id
                   WHERE u.id=? AND u.organization_id=? AND u.status='active' AND p.permission_key=? LIMIT 1""",
                (user_id, organization_id, permission_key),
            ).fetchone()
        return row is not None

    def create_duty(self, organization_id: str, department_id: str, title: str, description: str,
                    cadence: str, priority: str = "medium", owner_user_id: str | None = None,
                    metadata: dict[str, Any] | None = None, actor_user_id: str | None = None) -> dict[str, Any]:
        if priority not in {"low", "medium", "high", "critical"}:
            raise ValidationError("invalid priority")
        now, duty_id = _utcnow(), _id()
        with self._connection() as db:
            if actor_user_id:
                self._require(db, actor_user_id, organization_id, "duty.manage")
            self._assert_department(db, organization_id, department_id)
            db.execute("INSERT INTO duties VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (duty_id, organization_id, department_id, self._required(title, "title"),
                        self._required(description, "description"), self._required(cadence, "cadence"),
                        priority, owner_user_id, "active", json.dumps(metadata or {}, sort_keys=True), now, now))
            self._audit(db, organization_id, actor_user_id, "duty.created", "duty", duty_id, {"title": title})
            row = db.execute("SELECT * FROM duties WHERE id=?", (duty_id,)).fetchone()
        result = dict(row); result["metadata"] = json.loads(result.pop("metadata_json")); return result

    def create_kpi(self, organization_id: str, department_id: str, name: str, unit: str,
                   direction: str, target: float, period: str, owner_user_id: str | None = None,
                   actor_user_id: str | None = None) -> dict[str, Any]:
        if direction not in {"increase", "decrease", "maintain"}:
            raise ValidationError("invalid KPI direction")
        now, kpi_id = _utcnow(), _id()
        with self._connection() as db:
            if actor_user_id:
                self._require(db, actor_user_id, organization_id, "kpi.manage")
            self._assert_department(db, organization_id, department_id)
            db.execute("INSERT INTO kpis VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (kpi_id, organization_id, department_id, self._required(name, "name"),
                        self._required(unit, "unit"), direction, float(target), None,
                        self._required(period, "period"), owner_user_id, "active", now, now))
            self._audit(db, organization_id, actor_user_id, "kpi.created", "kpi", kpi_id, {"target": target})
            row = db.execute("SELECT * FROM kpis WHERE id=?", (kpi_id,)).fetchone()
        return dict(row)

    def update_kpi_value(self, kpi_id: str, value: float, actor_user_id: str) -> dict[str, Any]:
        with self._connection() as db:
            row = db.execute("SELECT * FROM kpis WHERE id=?", (kpi_id,)).fetchone()
            if row is None:
                raise KeyError("kpi not found")
            self._require(db, actor_user_id, row["organization_id"], "kpi.manage")
            db.execute("UPDATE kpis SET current_value=?, updated_at=? WHERE id=?", (float(value), _utcnow(), kpi_id))
            self._audit(db, row["organization_id"], actor_user_id, "kpi.value_updated", "kpi", kpi_id, {"value": value})
            updated = db.execute("SELECT * FROM kpis WHERE id=?", (kpi_id,)).fetchone()
        return dict(updated)

    def organization_snapshot(self, organization_id: str) -> dict[str, Any]:
        with self._connection() as db:
            self._assert_org(db, organization_id)
            counts = {}
            for table in ("departments", "users", "roles", "duties", "kpis"):
                counts[table] = db.execute(f"SELECT COUNT(*) total FROM {table} WHERE organization_id=?", (organization_id,)).fetchone()["total"]
            kpis = [dict(row) for row in db.execute("SELECT * FROM kpis WHERE organization_id=? AND status='active' ORDER BY name", (organization_id,))]
            duties = [dict(row) for row in db.execute("SELECT * FROM duties WHERE organization_id=? AND status='active' ORDER BY priority DESC, title", (organization_id,))]
        return {"organization": self.get_organization(organization_id), "counts": counts, "active_kpis": kpis, "active_duties": duties}

    def audit_events(self, organization_id: str, actor_user_id: str, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValidationError("limit must be between 1 and 1000")
        with self._connection() as db:
            self._require(db, actor_user_id, organization_id, "audit.read")
            rows = db.execute("SELECT * FROM audit_log WHERE organization_id=? ORDER BY id DESC LIMIT ?", (organization_id, limit)).fetchall()
        return [dict(row) | {"payload": json.loads(row["payload_json"])} for row in rows]

    @staticmethod
    def _assert_org(db: sqlite3.Connection, organization_id: str) -> None:
        if db.execute("SELECT 1 FROM organizations WHERE id=? AND status='active'", (organization_id,)).fetchone() is None:
            raise KeyError("active organization not found")

    @staticmethod
    def _assert_department(db: sqlite3.Connection, organization_id: str, department_id: str) -> None:
        if db.execute("SELECT 1 FROM departments WHERE id=? AND organization_id=? AND status='active'", (department_id, organization_id)).fetchone() is None:
            raise KeyError("active department not found")

    @staticmethod
    def _require(db: sqlite3.Connection, user_id: str, organization_id: str, permission_key: str) -> None:
        row = db.execute(
            """SELECT 1 FROM users u JOIN user_roles ur ON ur.user_id=u.id
               JOIN role_permissions rp ON rp.role_id=ur.role_id JOIN permissions p ON p.id=rp.permission_id
               WHERE u.id=? AND u.organization_id=? AND u.status='active' AND p.permission_key=? LIMIT 1""",
            (user_id, organization_id, permission_key),
        ).fetchone()
        if row is None:
            raise PermissionDenied(f"permission required: {permission_key}")
