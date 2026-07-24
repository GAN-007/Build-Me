from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator


class ValidationError(ValueError):
    pass


class AuthenticationError(RuntimeError):
    pass


class AuthorizationError(RuntimeError):
    pass


class ConflictError(RuntimeError):
    pass


def _id() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class ControlPlane:
    """Durable enterprise identity, policy, and workflow state machine.

    It extends the organization database without changing the legacy autonomous
    loop. Credentials are one-time secrets stored as scrypt hashes. Policies are
    deny-overrides. Workflow runs are idempotent, approval-aware, leased, retried,
    and fully evented.
    """

    def __init__(self, database: str | Path = "data/organization.db") -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @contextmanager
    def _connection(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.database, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=30000")
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
                CREATE TABLE IF NOT EXISTS api_credentials (
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
                    user_id TEXT NOT NULL, name TEXT NOT NULL,
                    token_prefix TEXT NOT NULL UNIQUE, token_hash BLOB NOT NULL,
                    token_salt BLOB NOT NULL, scopes_json TEXT NOT NULL,
                    expires_at TEXT, last_used_at TEXT, revoked_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS policy_rules (
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
                    name TEXT NOT NULL, effect TEXT NOT NULL CHECK(effect IN ('allow','deny')),
                    action_pattern TEXT NOT NULL, resource_pattern TEXT NOT NULL,
                    priority INTEGER NOT NULL, conditions_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','disabled')),
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    UNIQUE(organization_id,name),
                    FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS workflow_definitions (
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
                    department_id TEXT, name TEXT NOT NULL, version INTEGER NOT NULL,
                    description TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('draft','active','retired')),
                    input_schema_json TEXT NOT NULL, approval_required INTEGER NOT NULL,
                    created_by_user_id TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    UNIQUE(organization_id,name,version),
                    FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY(department_id) REFERENCES departments(id) ON DELETE SET NULL,
                    FOREIGN KEY(created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS workflow_definition_steps (
                    id TEXT PRIMARY KEY, definition_id TEXT NOT NULL,
                    step_key TEXT NOT NULL, position INTEGER NOT NULL,
                    name TEXT NOT NULL, handler TEXT NOT NULL,
                    required_permission TEXT NOT NULL, timeout_seconds INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL, depends_on_json TEXT NOT NULL,
                    UNIQUE(definition_id,step_key), UNIQUE(definition_id,position),
                    FOREIGN KEY(definition_id) REFERENCES workflow_definitions(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS workflow_runs (
                    id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
                    definition_id TEXT NOT NULL, requested_by_user_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL, state TEXT NOT NULL,
                    input_json TEXT NOT NULL, output_json TEXT, error_json TEXT,
                    approval_required INTEGER NOT NULL, approved_by_user_id TEXT,
                    approved_at TEXT, started_at TEXT, completed_at TEXT,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    UNIQUE(organization_id,idempotency_key),
                    FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY(definition_id) REFERENCES workflow_definitions(id) ON DELETE RESTRICT,
                    FOREIGN KEY(requested_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
                    FOREIGN KEY(approved_by_user_id) REFERENCES users(id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS workflow_run_steps (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL,
                    definition_step_id TEXT NOT NULL, step_key TEXT NOT NULL,
                    position INTEGER NOT NULL, state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL, lease_owner TEXT,
                    lease_token_hash TEXT, lease_expires_at TEXT,
                    input_json TEXT NOT NULL, output_json TEXT, error_json TEXT,
                    started_at TEXT, completed_at TEXT, updated_at TEXT NOT NULL,
                    UNIQUE(run_id,step_key),
                    FOREIGN KEY(run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE,
                    FOREIGN KEY(definition_step_id) REFERENCES workflow_definition_steps(id) ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS workflow_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL, run_id TEXT NOT NULL,
                    step_id TEXT, actor_user_id TEXT, event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL, created_at TEXT NOT NULL,
                    FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY(run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE,
                    FOREIGN KEY(step_id) REFERENCES workflow_run_steps(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_credentials_prefix ON api_credentials(token_prefix);
                CREATE INDEX IF NOT EXISTS idx_policy_lookup ON policy_rules(organization_id,status,priority);
                CREATE INDEX IF NOT EXISTS idx_runs_org_state ON workflow_runs(organization_id,state,created_at);
                CREATE INDEX IF NOT EXISTS idx_steps_lease ON workflow_run_steps(state,lease_expires_at,position);
                CREATE INDEX IF NOT EXISTS idx_events_run ON workflow_events(run_id,id);
                """
            )

    @staticmethod
    def _required(value: str, field: str) -> str:
        value = value.strip()
        if not value:
            raise ValidationError(f"{field} is required")
        return value

    @staticmethod
    def _match(pattern: str, value: str) -> bool:
        return pattern == "*" or (pattern.endswith("*") and value.startswith(pattern[:-1])) or hmac.compare_digest(pattern, value)

    @staticmethod
    def _derive(token: str, salt: bytes) -> bytes:
        return hashlib.scrypt(token.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    def _active_user(self, db: sqlite3.Connection, organization_id: str, user_id: str) -> sqlite3.Row:
        user = db.execute(
            "SELECT * FROM users WHERE id=? AND organization_id=? AND status='active'",
            (user_id, organization_id),
        ).fetchone()
        if user is None:
            raise AuthenticationError("active organization user required")
        return user

    def _rbac(self, db: sqlite3.Connection, organization_id: str, user_id: str, permission: str) -> bool:
        return db.execute(
            """SELECT 1 FROM users u JOIN user_roles ur ON ur.user_id=u.id
            JOIN roles r ON r.id=ur.role_id AND r.organization_id=u.organization_id
            JOIN role_permissions rp ON rp.role_id=r.id JOIN permissions p ON p.id=rp.permission_id
            WHERE u.id=? AND u.organization_id=? AND u.status='active' AND p.permission_key=? LIMIT 1""",
            (user_id, organization_id, permission),
        ).fetchone() is not None

    def _authorized(self, db: sqlite3.Connection, organization_id: str, user_id: str,
                    action: str, resource_type: str, context: dict[str, Any] | None = None) -> bool:
        user = self._active_user(db, organization_id, user_id)
        if not self._rbac(db, organization_id, user_id, action):
            return False
        rules = db.execute(
            "SELECT * FROM policy_rules WHERE organization_id=? AND status='active' ORDER BY priority,id",
            (organization_id,),
        ).fetchall()
        if not rules:
            return True
        values = {**(context or {}), "user_type": user["user_type"]}
        allowed = False
        for rule in rules:
            if not self._match(rule["action_pattern"], action) or not self._match(rule["resource_pattern"], resource_type):
                continue
            conditions = json.loads(rule["conditions_json"])
            if not all(values.get(key) == value for key, value in conditions.items()):
                continue
            if rule["effect"] == "deny":
                return False
            allowed = True
        return allowed

    def create_api_credential(self, organization_id: str, user_id: str, name: str,
                              scopes: list[str], expires_at: str | None = None) -> dict[str, Any]:
        scopes = sorted({self._required(scope, "scope") for scope in scopes})
        if not scopes:
            raise ValidationError("at least one scope is required")
        if expires_at:
            expiry = datetime.fromisoformat(expires_at)
            if expiry.tzinfo is None or expiry <= _now():
                raise ValidationError("expires_at must be a future timezone-aware datetime")
        prefix = f"bm_{secrets.token_urlsafe(9)}"
        token = f"{prefix}.{secrets.token_urlsafe(32)}"
        salt = secrets.token_bytes(16)
        credential_id = _id()
        with self._connection() as db:
            self._active_user(db, organization_id, user_id)
            db.execute(
                """INSERT INTO api_credentials(id,organization_id,user_id,name,token_prefix,token_hash,
                token_salt,scopes_json,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (credential_id, organization_id, user_id, self._required(name, "name"), prefix,
                 self._derive(token, salt), salt, _json(scopes), expires_at, _iso()),
            )
        return {"id": credential_id, "token": token, "token_prefix": prefix, "scopes": scopes, "expires_at": expires_at}

    def authenticate(self, token: str, required_scope: str | None = None) -> dict[str, Any]:
        prefix, separator, _ = token.partition(".")
        if not separator or not prefix.startswith("bm_"):
            raise AuthenticationError("invalid credential")
        with self._connection() as db:
            row = db.execute(
                """SELECT c.*,u.display_name,u.user_type,u.status AS user_status FROM api_credentials c
                JOIN users u ON u.id=c.user_id AND u.organization_id=c.organization_id
                WHERE c.token_prefix=?""", (prefix,),
            ).fetchone()
            if row is None or row["revoked_at"] or row["user_status"] != "active":
                raise AuthenticationError("invalid credential")
            if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) <= _now():
                raise AuthenticationError("credential expired")
            if not hmac.compare_digest(self._derive(token, row["token_salt"]), row["token_hash"]):
                raise AuthenticationError("invalid credential")
            scopes = json.loads(row["scopes_json"])
            if required_scope and not any(self._match(scope, required_scope) for scope in scopes):
                raise AuthorizationError("credential scope denied")
            db.execute("UPDATE api_credentials SET last_used_at=? WHERE id=?", (_iso(), row["id"]))
            return {"credential_id": row["id"], "organization_id": row["organization_id"],
                    "user_id": row["user_id"], "display_name": row["display_name"],
                    "user_type": row["user_type"], "scopes": scopes}

    def create_policy_rule(self, organization_id: str, actor_user_id: str, name: str,
                           effect: str, action_pattern: str, resource_pattern: str,
                           conditions: dict[str, Any] | None = None, priority: int = 100) -> dict[str, Any]:
        if effect not in {"allow", "deny"} or not 0 <= priority <= 10000:
            raise ValidationError("invalid policy effect or priority")
        conditions = conditions or {}
        if set(conditions) - {"user_type", "department_id", "owner_user_id"}:
            raise ValidationError("unsupported policy condition")
        rule_id, now = _id(), _iso()
        with self._connection() as db:
            if not self._rbac(db, organization_id, actor_user_id, "role.manage"):
                raise AuthorizationError("role.manage required")
            db.execute(
                """INSERT INTO policy_rules(id,organization_id,name,effect,action_pattern,resource_pattern,
                priority,conditions_json,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?, 'active',?,?)""",
                (rule_id, organization_id, self._required(name, "name"), effect,
                 self._required(action_pattern, "action_pattern"), self._required(resource_pattern, "resource_pattern"),
                 priority, _json(conditions), now, now),
            )
        return {"id": rule_id, "effect": effect, "conditions": conditions}

    def authorize(self, organization_id: str, user_id: str, action: str,
                  resource_type: str, context: dict[str, Any] | None = None) -> bool:
        with self._connection() as db:
            return self._authorized(db, organization_id, user_id, action, resource_type, context)

    def create_workflow_definition(self, organization_id: str, actor_user_id: str,
                                   name: str, description: str, steps: list[dict[str, Any]],
                                   department_id: str | None = None,
                                   input_schema: dict[str, Any] | None = None,
                                   approval_required: bool = False) -> dict[str, Any]:
        if not steps:
            raise ValidationError("workflow requires at least one step")
        keys = [self._required(str(step.get("key", "")), "step.key") for step in steps]
        if len(keys) != len(set(keys)):
            raise ValidationError("workflow step keys must be unique")
        normalized = []
        for position, step in enumerate(steps):
            dependencies = list(step.get("depends_on", []))
            if any(dep not in keys for dep in dependencies) or keys[position] in dependencies:
                raise ValidationError("invalid workflow dependency")
            timeout = int(step.get("timeout_seconds", 900))
            attempts = int(step.get("max_attempts", 3))
            if not 1 <= timeout <= 86400 or not 1 <= attempts <= 100:
                raise ValidationError("step timeout or attempts out of range")
            normalized.append((keys[position], position, self._required(str(step.get("name", "")), "step.name"),
                               self._required(str(step.get("handler", "")), "step.handler"),
                               self._required(str(step.get("required_permission", "")), "step.required_permission"),
                               timeout, attempts, dependencies))
        definition_id, now = _id(), _iso()
        with self._connection() as db:
            if not self._authorized(db, organization_id, actor_user_id, "duty.manage", "workflow_definition",
                                    {"department_id": department_id}):
                raise AuthorizationError("workflow definition denied")
            version = int(db.execute(
                "SELECT COALESCE(MAX(version),0)+1 v FROM workflow_definitions WHERE organization_id=? AND name=?",
                (organization_id, name.strip()),
            ).fetchone()["v"])
            db.execute(
                """INSERT INTO workflow_definitions(id,organization_id,department_id,name,version,description,status,
                input_schema_json,approval_required,created_by_user_id,created_at,updated_at)
                VALUES(?,?,?,?,?,?, 'draft',?,?,?,?,?)""",
                (definition_id, organization_id, department_id, self._required(name, "name"), version,
                 description.strip(), _json(input_schema or {}), int(approval_required), actor_user_id, now, now),
            )
            for key, position, step_name, handler, permission, timeout, attempts, dependencies in normalized:
                db.execute(
                    """INSERT INTO workflow_definition_steps(id,definition_id,step_key,position,name,handler,
                    required_permission,timeout_seconds,max_attempts,depends_on_json) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (_id(), definition_id, key, position, step_name, handler, permission, timeout, attempts, _json(dependencies)),
                )
        return {"id": definition_id, "name": name, "version": version, "status": "draft"}

    def activate_workflow_definition(self, organization_id: str, actor_user_id: str, definition_id: str) -> None:
        with self._connection() as db:
            if not self._authorized(db, organization_id, actor_user_id, "duty.manage", "workflow_definition"):
                raise AuthorizationError("workflow activation denied")
            if db.execute("UPDATE workflow_definitions SET status='active',updated_at=? WHERE id=? AND organization_id=? AND status='draft'",
                          (_iso(), definition_id, organization_id)).rowcount != 1:
                raise ConflictError("draft workflow definition not found")

    def start_workflow(self, organization_id: str, requested_by_user_id: str,
                       definition_id: str, idempotency_key: str, input_data: dict[str, Any]) -> dict[str, Any]:
        idempotency_key = self._required(idempotency_key, "idempotency_key")
        with self._connection(immediate=True) as db:
            existing = db.execute("SELECT * FROM workflow_runs WHERE organization_id=? AND idempotency_key=?",
                                  (organization_id, idempotency_key)).fetchone()
            if existing:
                return dict(existing)
            definition = db.execute("SELECT * FROM workflow_definitions WHERE id=? AND organization_id=? AND status='active'",
                                    (definition_id, organization_id)).fetchone()
            if definition is None:
                raise ValidationError("active workflow definition not found")
            self._active_user(db, organization_id, requested_by_user_id)
            run_id, now = _id(), _iso()
            state = "awaiting_approval" if definition["approval_required"] else "runnable"
            db.execute(
                """INSERT INTO workflow_runs(id,organization_id,definition_id,requested_by_user_id,idempotency_key,state,
                input_json,approval_required,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (run_id, organization_id, definition_id, requested_by_user_id, idempotency_key, state,
                 _json(input_data), definition["approval_required"], now, now),
            )
            for step in db.execute("SELECT * FROM workflow_definition_steps WHERE definition_id=? ORDER BY position",
                                   (definition_id,)).fetchall():
                dependencies = json.loads(step["depends_on_json"])
                step_state = "pending" if dependencies or definition["approval_required"] else "runnable"
                db.execute(
                    """INSERT INTO workflow_run_steps(id,run_id,definition_step_id,step_key,position,state,max_attempts,
                    input_json,updated_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (_id(), run_id, step["id"], step["step_key"], step["position"], step_state,
                     step["max_attempts"], _json(input_data), now),
                )
            self._event(db, organization_id, run_id, None, requested_by_user_id, "workflow.started", {"state": state})
            return dict(db.execute("SELECT * FROM workflow_runs WHERE id=?", (run_id,)).fetchone())

    def approve_workflow(self, organization_id: str, run_id: str, approver_user_id: str) -> None:
        with self._connection() as db:
            if not self._authorized(db, organization_id, approver_user_id, "duty.manage", "workflow_approval"):
                raise AuthorizationError("workflow approval denied")
            if db.execute("""UPDATE workflow_runs SET state='runnable',approved_by_user_id=?,approved_at=?,updated_at=?
                          WHERE id=? AND organization_id=? AND state='awaiting_approval'""",
                          (approver_user_id, _iso(), _iso(), run_id, organization_id)).rowcount != 1:
                raise ConflictError("workflow is not awaiting approval")
            db.execute("""UPDATE workflow_run_steps SET state='runnable',updated_at=? WHERE run_id=? AND state='pending'
                       AND json_array_length((SELECT depends_on_json FROM workflow_definition_steps d
                       WHERE d.id=workflow_run_steps.definition_step_id))=0""", (_iso(), run_id))
            self._event(db, organization_id, run_id, None, approver_user_id, "workflow.approved", {})

    def lease_next_step(self, organization_id: str, worker_id: str, lease_seconds: int = 120) -> dict[str, Any] | None:
        if not 15 <= lease_seconds <= 3600:
            raise ValidationError("lease_seconds must be between 15 and 3600")
        now, expires = _now(), _now() + timedelta(seconds=lease_seconds)
        with self._connection(immediate=True) as db:
            step = db.execute(
                """SELECT s.*,d.handler,d.required_permission,d.timeout_seconds FROM workflow_run_steps s
                JOIN workflow_runs r ON r.id=s.run_id JOIN workflow_definition_steps d ON d.id=s.definition_step_id
                WHERE r.organization_id=? AND r.state IN ('runnable','running')
                AND (s.state='runnable' OR (s.state='leased' AND s.lease_expires_at<?))
                ORDER BY r.created_at,s.position LIMIT 1""", (organization_id, _iso(now)),
            ).fetchone()
            if step is None:
                return None
            token = secrets.token_urlsafe(24)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if db.execute("""UPDATE workflow_run_steps SET state='leased',lease_owner=?,lease_token_hash=?,
                          lease_expires_at=?,updated_at=? WHERE id=? AND
                          (state='runnable' OR (state='leased' AND lease_expires_at<?))""",
                          (worker_id, token_hash, _iso(expires), _iso(now), step["id"], _iso(now))).rowcount != 1:
                return None
            db.execute("UPDATE workflow_runs SET state='running',started_at=COALESCE(started_at,?),updated_at=? WHERE id=?",
                       (_iso(now), _iso(now), step["run_id"]))
            result = dict(step)
            result.update({"lease_token": token, "lease_expires_at": _iso(expires)})
            return result

    def begin_step(self, step_id: str, worker_id: str, lease_token: str) -> None:
        token_hash = hashlib.sha256(lease_token.encode()).hexdigest()
        with self._connection() as db:
            if db.execute("""UPDATE workflow_run_steps SET state='running',attempt_count=attempt_count+1,
                          started_at=COALESCE(started_at,?),updated_at=? WHERE id=? AND state='leased'
                          AND lease_owner=? AND lease_token_hash=? AND lease_expires_at>=?""",
                          (_iso(), _iso(), step_id, worker_id, token_hash, _iso())).rowcount != 1:
                raise ConflictError("valid active lease required")

    def complete_step(self, step_id: str, worker_id: str, lease_token: str, output: dict[str, Any]) -> None:
        token_hash = hashlib.sha256(lease_token.encode()).hexdigest()
        with self._connection() as db:
            step = db.execute("SELECT s.*,r.organization_id FROM workflow_run_steps s JOIN workflow_runs r ON r.id=s.run_id WHERE s.id=?",
                              (step_id,)).fetchone()
            if step is None:
                raise ValidationError("step not found")
            if db.execute("""UPDATE workflow_run_steps SET state='succeeded',output_json=?,completed_at=?,updated_at=?,
                          lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL
                          WHERE id=? AND state='running' AND lease_owner=? AND lease_token_hash=?""",
                          (_json(output), _iso(), _iso(), step_id, worker_id, token_hash)).rowcount != 1:
                raise ConflictError("running leased step required")
            self._event(db, step["organization_id"], step["run_id"], step_id, None, "step.succeeded", output)
            self._advance(db, step["run_id"])

    def fail_step(self, step_id: str, worker_id: str, lease_token: str,
                  error: dict[str, Any], retryable: bool = True) -> str:
        token_hash = hashlib.sha256(lease_token.encode()).hexdigest()
        with self._connection() as db:
            step = db.execute("SELECT s.*,r.organization_id FROM workflow_run_steps s JOIN workflow_runs r ON r.id=s.run_id WHERE s.id=?",
                              (step_id,)).fetchone()
            if step is None or step["state"] != "running" or step["lease_owner"] != worker_id or not hmac.compare_digest(step["lease_token_hash"] or "", token_hash):
                raise ConflictError("running leased step required")
            state = "dead_letter" if not retryable or step["attempt_count"] >= step["max_attempts"] else "runnable"
            db.execute("""UPDATE workflow_run_steps SET state=?,error_json=?,updated_at=?,lease_owner=NULL,
                       lease_token_hash=NULL,lease_expires_at=NULL WHERE id=?""", (state, _json(error), _iso(), step_id))
            self._event(db, step["organization_id"], step["run_id"], step_id, None, f"step.{state}", error)
            if state == "dead_letter":
                db.execute("UPDATE workflow_runs SET state='dead_letter',error_json=?,completed_at=?,updated_at=? WHERE id=?",
                           (_json(error), _iso(), _iso(), step["run_id"]))
            return state

    def get_workflow_run(self, organization_id: str, user_id: str, run_id: str) -> dict[str, Any]:
        with self._connection() as db:
            if not self._authorized(db, organization_id, user_id, "duty.manage", "workflow_run"):
                raise AuthorizationError("workflow read denied")
            run = db.execute("SELECT * FROM workflow_runs WHERE id=? AND organization_id=?", (run_id, organization_id)).fetchone()
            if run is None:
                raise ValidationError("workflow run not found")
            return {"run": dict(run),
                    "steps": [dict(row) for row in db.execute("SELECT * FROM workflow_run_steps WHERE run_id=? ORDER BY position", (run_id,))],
                    "events": [dict(row) for row in db.execute("SELECT * FROM workflow_events WHERE run_id=? ORDER BY id", (run_id,))]}

    def _advance(self, db: sqlite3.Connection, run_id: str) -> None:
        succeeded = {row["step_key"] for row in db.execute("SELECT step_key FROM workflow_run_steps WHERE run_id=? AND state='succeeded'", (run_id,))}
        for row in db.execute("""SELECT s.id,d.depends_on_json FROM workflow_run_steps s
                              JOIN workflow_definition_steps d ON d.id=s.definition_step_id
                              WHERE s.run_id=? AND s.state='pending'""", (run_id,)):
            if set(json.loads(row["depends_on_json"])).issubset(succeeded):
                db.execute("UPDATE workflow_run_steps SET state='runnable',updated_at=? WHERE id=?", (_iso(), row["id"]))
        remaining = db.execute("SELECT COUNT(*) c FROM workflow_run_steps WHERE run_id=? AND state NOT IN ('succeeded','skipped','cancelled')", (run_id,)).fetchone()["c"]
        if remaining == 0:
            outputs = {row["step_key"]: json.loads(row["output_json"] or "{}") for row in db.execute("SELECT step_key,output_json FROM workflow_run_steps WHERE run_id=? ORDER BY position", (run_id,))}
            db.execute("UPDATE workflow_runs SET state='succeeded',output_json=?,completed_at=?,updated_at=? WHERE id=?",
                       (_json(outputs), _iso(), _iso(), run_id))

    @staticmethod
    def _event(db: sqlite3.Connection, organization_id: str, run_id: str,
               step_id: str | None, actor_user_id: str | None,
               event_type: str, payload: dict[str, Any]) -> None:
        db.execute("""INSERT INTO workflow_events(organization_id,run_id,step_id,actor_user_id,event_type,payload_json,created_at)
                   VALUES(?,?,?,?,?,?,?)""", (organization_id, run_id, step_id, actor_user_id, event_type, _json(payload), _iso()))
