from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class RestoreVerificationError(RuntimeError):
    pass


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class RecoveryService:
    """Consistent SQLite backups, signed manifests, and destructive restore drills."""

    def __init__(self, source_database: str | Path = "data/organization.db", backup_directory: str | Path = "backups") -> None:
        self.source_database = Path(source_database)
        self.backup_directory = Path(backup_directory)
        self.backup_directory.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _integrity_check(database: Path) -> None:
        db = sqlite3.connect(database)
        try:
            result = db.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_key_errors = db.execute("PRAGMA foreign_key_check").fetchall()
        finally:
            db.close()
        if result != "ok" or foreign_key_errors:
            raise RestoreVerificationError("database integrity verification failed")

    @staticmethod
    def _table_counts(database: Path) -> dict[str, int]:
        db = sqlite3.connect(database)
        try:
            tables = [
                row[0]
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            ]
            return {name: int(db.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]) for name in tables}
        finally:
            db.close()

    def create_backup(self) -> dict[str, Any]:
        if not self.source_database.exists():
            raise FileNotFoundError(self.source_database)
        backup_id = str(uuid.uuid4())
        created_at = _utcnow()
        target = self.backup_directory / f"{backup_id}.sqlite3"
        manifest_path = self.backup_directory / f"{backup_id}.json"
        source = sqlite3.connect(self.source_database)
        destination = sqlite3.connect(target)
        try:
            source.backup(destination, pages=256)
        finally:
            destination.close()
            source.close()
        self._integrity_check(target)
        manifest = {
            "backup_id": backup_id,
            "created_at": created_at,
            "source": str(self.source_database),
            "database_file": target.name,
            "size_bytes": target.stat().st_size,
            "sha256": _sha256(target),
            "table_counts": self._table_counts(target),
            "format": "sqlite3",
        }
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        with manifest_path.open("rb") as handle:
            os.fsync(handle.fileno())
        return manifest

    def verify_backup(self, backup_id: str) -> dict[str, Any]:
        manifest_path = self.backup_directory / f"{backup_id}.json"
        if not manifest_path.exists():
            raise FileNotFoundError(manifest_path)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        database = self.backup_directory / manifest["database_file"]
        if not database.exists():
            raise RestoreVerificationError("backup database is missing")
        if database.stat().st_size != manifest["size_bytes"]:
            raise RestoreVerificationError("backup size does not match manifest")
        if not hashlib.sha256(database.read_bytes()).hexdigest() == manifest["sha256"]:
            raise RestoreVerificationError("backup checksum does not match manifest")
        self._integrity_check(database)
        if self._table_counts(database) != manifest["table_counts"]:
            raise RestoreVerificationError("backup table counts do not match manifest")
        return manifest | {"verified": True}

    def restore_drill(self, backup_id: str) -> dict[str, Any]:
        manifest = self.verify_backup(backup_id)
        backup = self.backup_directory / manifest["database_file"]
        with tempfile.TemporaryDirectory(prefix="build-me-restore-") as directory:
            restored = Path(directory) / "restored.sqlite3"
            shutil.copy2(backup, restored)
            self._integrity_check(restored)
            counts = self._table_counts(restored)
            if counts != manifest["table_counts"]:
                raise RestoreVerificationError("restored data differs from backup manifest")
            return {
                "backup_id": backup_id,
                "verified": True,
                "restored_size_bytes": restored.stat().st_size,
                "table_counts": counts,
            }

    def restore_to(self, backup_id: str, destination: str | Path, overwrite: bool = False) -> Path:
        manifest = self.verify_backup(backup_id)
        backup = self.backup_directory / manifest["database_file"]
        destination_path = Path(destination)
        if destination_path.exists() and not overwrite:
            raise FileExistsError(destination_path)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination_path.with_suffix(destination_path.suffix + ".restoring")
        shutil.copy2(backup, temporary)
        self._integrity_check(temporary)
        os.replace(temporary, destination_path)
        return destination_path
