from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator


class InvalidSession(RuntimeError):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat()


class IdentityService:
    """Secure browser and service sessions with rotation and revocation.

    Only token prefixes, salts, and scrypt hashes are stored. Raw session tokens are
    returned once to the caller and never written to the database.
    """

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
                CREATE TABLE IF NOT EXISTS identity_sessions (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    token_prefix TEXT NOT NULL UNIQUE,
                    token_salt BLOB NOT NULL,
                    token_hash BLOB NOT NULL,
                    auth_method TEXT NOT NULL CHECK(auth_method IN ('passwordless','oidc','saml','service')),
                    assurance_level INTEGER NOT NULL CHECK(assurance_level BETWEEN 1 AND 3),
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    absolute_expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    revoked_reason TEXT,
                    rotated_from_session_id TEXT,
                    FOREIGN KEY(rotated_from_session_id) REFERENCES identity_sessions(id) ON DELETE SET NULL
                );
                CREATE INDEX IF NOT EXISTS idx_identity_sessions_user
                    ON identity_sessions(organization_id, user_id, revoked_at, expires_at);
                CREATE TABLE IF NOT EXISTS identity_security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL,
                    user_id TEXT,
                    session_id TEXT,
                    event_type TEXT NOT NULL,
                    ip_address TEXT,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _derive(token: str, salt: bytes) -> bytes:
        return hashlib.scrypt(token.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)

    def create_session(
        self,
        organization_id: str,
        user_id: str,
        auth_method: str,
        assurance_level: int,
        idle_minutes: int = 30,
        absolute_hours: int = 12,
        ip_address: str | None = None,
        user_agent: str | None = None,
        rotated_from_session_id: str | None = None,
    ) -> dict[str, str | int | None]:
        if auth_method not in {"passwordless", "oidc", "saml", "service"}:
            raise ValueError("unsupported auth_method")
        if assurance_level not in {1, 2, 3}:
            raise ValueError("assurance_level must be 1, 2, or 3")
        if not 1 <= idle_minutes <= 1440 or not 1 <= absolute_hours <= 720:
            raise ValueError("invalid session lifetime")
        now = _utcnow()
        session_id = str(uuid.uuid4())
        raw_token = secrets.token_urlsafe(48)
        prefix = raw_token[:16]
        salt = secrets.token_bytes(16)
        token_hash = self._derive(raw_token, salt)
        expires_at = now + timedelta(minutes=idle_minutes)
        absolute_expires_at = now + timedelta(hours=absolute_hours)
        if expires_at > absolute_expires_at:
            expires_at = absolute_expires_at
        with self._connection(immediate=True) as db:
            db.execute(
                """INSERT INTO identity_sessions(
                     id,organization_id,user_id,token_prefix,token_salt,token_hash,
                     auth_method,assurance_level,ip_address,user_agent,created_at,last_seen_at,
                     expires_at,absolute_expires_at,revoked_at,revoked_reason,rotated_from_session_id
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    session_id,
                    organization_id,
                    user_id,
                    prefix,
                    salt,
                    token_hash,
                    auth_method,
                    assurance_level,
                    ip_address,
                    user_agent,
                    _iso(now),
                    _iso(now),
                    _iso(expires_at),
                    _iso(absolute_expires_at),
                    None,
                    None,
                    rotated_from_session_id,
                ),
            )
            db.execute(
                """INSERT INTO identity_security_events(
                     organization_id,user_id,session_id,event_type,ip_address,created_at
                   ) VALUES(?,?,?,?,?,?)""",
                (organization_id, user_id, session_id, "session.created", ip_address, _iso(now)),
            )
        return {
            "session_id": session_id,
            "token": raw_token,
            "expires_at": _iso(expires_at),
            "absolute_expires_at": _iso(absolute_expires_at),
            "assurance_level": assurance_level,
        }

    def authenticate(
        self,
        token: str,
        required_assurance: int = 1,
        idle_minutes: int = 30,
        ip_address: str | None = None,
    ) -> dict[str, object]:
        if not token or len(token) < 32:
            raise InvalidSession("invalid session")
        now = _utcnow()
        prefix = token[:16]
        with self._connection(immediate=True) as db:
            row = db.execute("SELECT * FROM identity_sessions WHERE token_prefix=?", (prefix,)).fetchone()
            valid = row is not None and hmac.compare_digest(self._derive(token, row["token_salt"]), row["token_hash"])
            if not valid:
                raise InvalidSession("invalid session")
            if row["revoked_at"] is not None:
                raise InvalidSession("session revoked")
            if datetime.fromisoformat(row["expires_at"]) <= now or datetime.fromisoformat(row["absolute_expires_at"]) <= now:
                raise InvalidSession("session expired")
            if row["assurance_level"] < required_assurance:
                raise InvalidSession("step-up authentication required")
            absolute = datetime.fromisoformat(row["absolute_expires_at"])
            refreshed = min(now + timedelta(minutes=idle_minutes), absolute)
            db.execute(
                "UPDATE identity_sessions SET last_seen_at=?, expires_at=? WHERE id=?",
                (_iso(now), _iso(refreshed), row["id"]),
            )
            result = dict(row)
            result["expires_at"] = _iso(refreshed)
            result.pop("token_salt", None)
            result.pop("token_hash", None)
            return result

    def revoke_session(self, session_id: str, reason: str, actor_user_id: str | None = None) -> None:
        now = _iso(_utcnow())
        with self._connection(immediate=True) as db:
            row = db.execute("SELECT * FROM identity_sessions WHERE id=?", (session_id,)).fetchone()
            if row is None:
                raise KeyError("session not found")
            db.execute(
                "UPDATE identity_sessions SET revoked_at=?, revoked_reason=? WHERE id=? AND revoked_at IS NULL",
                (now, reason.strip(), session_id),
            )
            db.execute(
                """INSERT INTO identity_security_events(
                     organization_id,user_id,session_id,event_type,metadata,created_at
                   ) VALUES(?,?,?,?,?,?)""",
                (row["organization_id"], actor_user_id or row["user_id"], session_id, "session.revoked", reason.strip(), now),
            )

    def rotate_session(
        self,
        token: str,
        idle_minutes: int = 30,
        absolute_hours: int = 12,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, str | int | None]:
        current = self.authenticate(token, required_assurance=1, idle_minutes=idle_minutes, ip_address=ip_address)
        replacement = self.create_session(
            organization_id=str(current["organization_id"]),
            user_id=str(current["user_id"]),
            auth_method=str(current["auth_method"]),
            assurance_level=int(current["assurance_level"]),
            idle_minutes=idle_minutes,
            absolute_hours=absolute_hours,
            ip_address=ip_address,
            user_agent=user_agent,
            rotated_from_session_id=str(current["id"]),
        )
        self.revoke_session(str(current["id"]), "rotated")
        return replacement

    def revoke_user_sessions(self, organization_id: str, user_id: str, reason: str) -> int:
        now = _iso(_utcnow())
        with self._connection(immediate=True) as db:
            cursor = db.execute(
                """UPDATE identity_sessions SET revoked_at=?, revoked_reason=?
                   WHERE organization_id=? AND user_id=? AND revoked_at IS NULL""",
                (now, reason.strip(), organization_id, user_id),
            )
            return cursor.rowcount
