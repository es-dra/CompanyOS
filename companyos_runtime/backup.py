"""Fail-closed online backup and restore for single-host runtime state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import IntegrityError
from .replay import ProjectionReplayer
from .schema import DDL, SCHEMA_VERSION
from .store import SQLiteStore
from .types import canonical_json, content_hash, utc_now


BACKUP_MANIFEST_VERSION = 1
_MANIFEST_KEYS = frozenset(
    {
        "manifest_version",
        "created_at",
        "backup_sha256",
        "size_bytes",
        "sqlite",
        "event_log",
        "core_projections",
        "recovery_set",
        "verification",
        "claim_boundary",
    }
)
_RECOVERY_SET = {
    "runtime_database_included": True,
    "external_adapter_receipts_included": False,
    "complete": False,
    "required_companion_state": [
        "each enabled external adapter receipt/idempotency ledger"
    ],
}
_VERIFICATION = {
    "sqlite_integrity": "passed",
    "event_chain": "passed",
    "core_projection_replay_readback": "passed",
}
_CLAIM_BOUNDARY = {
    "evidence_state": "runtime_verification",
    "non_claims": [
        "external_adapter_recovery_set_complete",
        "provider_health",
        "runtime_process_health",
        "disaster_recovery_qualified",
        "multi_host_backup",
        "cryptographically_attested_backup",
        "power_loss_durability_qualified",
    ],
}


@dataclass(frozen=True)
class _OwnedFile:
    """Identity of a file this invocation created with O_EXCL."""

    path: Path
    device: int
    inode: int

    @classmethod
    def from_descriptor(cls, path: Path, descriptor: int) -> _OwnedFile:
        created = os.fstat(descriptor)
        return cls(path=path, device=created.st_dev, inode=created.st_ino)

    def still_owns_path(self) -> bool:
        try:
            current = self.path.lstat()
        except FileNotFoundError:
            return False
        return (
            stat.S_ISREG(current.st_mode)
            and current.st_dev == self.device
            and current.st_ino == self.inode
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _existing_file(path: str | Path, field: str) -> Path:
    raw = Path(path).expanduser()
    if raw.is_symlink():
        raise IntegrityError(f"{field} must not be a symbolic link")
    candidate = raw.resolve()
    if not candidate.is_file():
        raise IntegrityError(f"{field} must be an existing regular file")
    return candidate


def _target_path(path: str | Path, field: str) -> Path:
    raw = Path(path).expanduser()
    if raw.is_symlink():
        raise IntegrityError(f"{field} must not be a symbolic link")
    candidate = raw.resolve()
    # Reuse the store's single-host/UNC boundary even before opening SQLite.
    SQLiteStore(candidate)
    if candidate.exists() or candidate.is_symlink():
        raise IntegrityError(f"{field} already exists; refusing to overwrite it")
    for suffix in ("-wal", "-shm", "-journal"):
        if Path(str(candidate) + suffix).exists():
            raise IntegrityError(
                f"{field} has an existing SQLite sidecar; refusing unknown state"
            )
    return candidate


def _read_only_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        path.as_uri() + "?mode=ro", uri=True, timeout=30, isolation_level=None
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _inspect_database(path: Path) -> dict[str, Any]:
    store = SQLiteStore(path)
    connection = _read_only_connection(path)
    try:
        connection.execute("BEGIN")
        integrity_rows = [
            str(row[0]) for row in connection.execute("PRAGMA integrity_check")
        ]
        if integrity_rows != ["ok"]:
            raise IntegrityError("SQLite integrity_check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise IntegrityError("SQLite foreign_key_check failed")
        migrations = connection.execute(
            "SELECT version, checksum FROM schema_migrations ORDER BY version"
        ).fetchall()
        if not migrations or int(migrations[-1]["version"]) != SCHEMA_VERSION:
            raise IntegrityError("runtime schema version is missing or unsupported")
        if str(migrations[-1]["checksum"]) != content_hash(DDL):
            raise IntegrityError("runtime schema migration checksum is invalid")
        schema_rows = connection.execute(
            "SELECT type, name, tbl_name, COALESCE(sql, '') AS sql "
            "FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' "
            "ORDER BY type, name"
        ).fetchall()
        schema_structure_digest = content_hash(
            [
                {
                    "type": str(row["type"]),
                    "name": str(row["name"]),
                    "table": str(row["tbl_name"]),
                    "sql": str(row["sql"]),
                }
                for row in schema_rows
            ]
        )
        event_count = store.verify_event_chain(connection)
        head = connection.execute(
            "SELECT seq, event_id, event_hash, recorded_at FROM events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        replayed = ProjectionReplayer(store).verify(connection=connection)
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()

    return {
        "sqlite": {
            "integrity_check": "ok",
            "schema_version": SCHEMA_VERSION,
            "schema_checksum": str(migrations[-1]["checksum"]),
            "schema_structure_digest": schema_structure_digest,
            "page_count": page_count,
            "page_size": page_size,
        },
        "event_log": {
            "count": event_count,
            "head_seq": int(head["seq"]) if head is not None else None,
            "head_event_id": str(head["event_id"]) if head is not None else None,
            "head_event_hash": str(head["event_hash"]) if head is not None else None,
            "head_recorded_at": str(head["recorded_at"]) if head is not None else None,
        },
        "core_projections": {
            "goals": len(replayed.goals),
            "runs": len(replayed.runs),
            "tasks": len(replayed.tasks),
        },
    }


def _exclusive_create(path: Path) -> _OwnedFile:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise IntegrityError(
            "target appeared concurrently; refusing to overwrite it"
        ) from exc
    try:
        return _OwnedFile.from_descriptor(path, descriptor)
    finally:
        os.close(descriptor)


def _remove_if_owned(owned: _OwnedFile) -> None:
    if not owned.still_owns_path():
        return
    try:
        owned.path.unlink()
    except FileNotFoundError:
        pass


def _remove_created_database(owned: _OwnedFile) -> None:
    if not owned.still_owns_path():
        return
    sidecars: list[_OwnedFile] = []
    for suffix in ("-wal", "-shm", "-journal"):
        candidate = Path(str(owned.path) + suffix)
        try:
            descriptor = os.open(candidate, os.O_RDONLY)
        except FileNotFoundError:
            continue
        try:
            sidecars.append(_OwnedFile.from_descriptor(candidate, descriptor))
        finally:
            os.close(descriptor)
    _remove_if_owned(owned)
    for sidecar in sidecars:
        _remove_if_owned(sidecar)


def _online_copy(source: Path, target: Path) -> _OwnedFile:
    owned = _exclusive_create(target)
    source_connection: sqlite3.Connection | None = None
    target_connection: sqlite3.Connection | None = None
    try:
        try:
            source_connection = _read_only_connection(source)
            target_connection = sqlite3.connect(
                target, timeout=30, isolation_level=None
            )
            source_connection.backup(target_connection)
            journal_mode = str(
                target_connection.execute("PRAGMA journal_mode = DELETE").fetchone()[0]
            ).casefold()
            if journal_mode != "delete":
                raise IntegrityError(
                    "backup could not be finalized as a standalone file"
                )
        finally:
            if target_connection is not None:
                target_connection.close()
            if source_connection is not None:
                source_connection.close()
        return owned
    except Exception:
        _remove_created_database(owned)
        raise


def _write_exclusive(path: Path, content: str) -> _OwnedFile:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise IntegrityError(
            "target appeared concurrently; refusing to overwrite it"
        ) from exc
    owned = _OwnedFile.from_descriptor(path, descriptor)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
        return owned
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        _remove_if_owned(owned)
        raise


def create_online_backup(
    source_database: str | Path,
    target_database: str | Path,
    *,
    manifest_path: str | Path | None = None,
) -> dict[str, Any]:
    """Create and verify one online snapshot without exposing source paths."""

    source = _existing_file(source_database, "source database")
    target = _target_path(target_database, "backup target")
    manifest = _target_path(
        manifest_path or Path(str(target) + ".manifest.json"), "backup manifest"
    )
    if source == target or source == manifest or target == manifest:
        raise IntegrityError("backup source, target, and manifest must be distinct")
    target_owner: _OwnedFile | None = None
    manifest_owner: _OwnedFile | None = None
    try:
        target_owner = _online_copy(source, target)
        inspected = _inspect_database(target)
        result: dict[str, Any] = {
            "manifest_version": BACKUP_MANIFEST_VERSION,
            "created_at": utc_now(),
            "backup_sha256": _sha256(target),
            "size_bytes": target.stat().st_size,
            **inspected,
            "recovery_set": dict(_RECOVERY_SET),
            "verification": dict(_VERIFICATION),
            "claim_boundary": dict(_CLAIM_BOUNDARY),
        }
        manifest_owner = _write_exclusive(manifest, canonical_json(result) + "\n")
        return result
    except Exception:
        if target_owner is not None:
            _remove_created_database(target_owner)
        if manifest_owner is not None:
            _remove_if_owned(manifest_owner)
        raise


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrityError("backup manifest is unreadable") from exc
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_KEYS:
        raise IntegrityError("backup manifest shape is invalid")
    if manifest.get("manifest_version") != BACKUP_MANIFEST_VERSION:
        raise IntegrityError("backup manifest version is unsupported")
    if not isinstance(manifest.get("created_at"), str):
        raise IntegrityError("backup manifest timestamp is invalid")
    try:
        created_at = datetime.fromisoformat(manifest["created_at"])
    except ValueError as exc:
        raise IntegrityError("backup manifest timestamp is invalid") from exc
    if created_at.tzinfo is None:
        raise IntegrityError("backup manifest timestamp must include a timezone")
    if re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("backup_sha256"))) is None:
        raise IntegrityError("backup manifest digest is invalid")
    size = manifest.get("size_bytes")
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise IntegrityError("backup manifest size is invalid")
    if manifest.get("recovery_set") != _RECOVERY_SET:
        raise IntegrityError("backup manifest recovery-set boundary is invalid")
    if manifest.get("verification") != _VERIFICATION:
        raise IntegrityError("backup manifest verification boundary is invalid")
    if manifest.get("claim_boundary") != _CLAIM_BOUNDARY:
        raise IntegrityError("backup manifest claim boundary is invalid")
    return manifest


def _assert_manifest_matches(
    backup: Path, manifest: dict[str, Any], inspected: dict[str, Any]
) -> None:
    expected = {
        "backup_sha256": _sha256(backup),
        "size_bytes": backup.stat().st_size,
        "sqlite": inspected["sqlite"],
        "event_log": inspected["event_log"],
        "core_projections": inspected["core_projections"],
    }
    mismatches = [key for key, value in expected.items() if manifest.get(key) != value]
    if mismatches:
        raise IntegrityError(
            "backup does not match verified manifest: " + ", ".join(sorted(mismatches))
        )


def restore_backup(
    backup_database: str | Path,
    *,
    manifest_path: str | Path | None = None,
    target_database: str | Path | None = None,
) -> dict[str, Any]:
    """Restore only into a new target and verify integrity plus replay readback."""

    backup = _existing_file(backup_database, "backup database")
    manifest_file = _existing_file(
        manifest_path or Path(str(backup) + ".manifest.json"), "backup manifest"
    )
    default_target = backup.with_name(f"{backup.stem}.restored{backup.suffix or '.db'}")
    target = _target_path(target_database or default_target, "restore target")
    if target in {backup, manifest_file}:
        raise IntegrityError("restore target must be distinct from backup files")

    manifest = _load_manifest(manifest_file)
    backup_inspection = _inspect_database(backup)
    _assert_manifest_matches(backup, manifest, backup_inspection)
    target_owner: _OwnedFile | None = None
    try:
        target_owner = _online_copy(backup, target)
        restored = _inspect_database(target)
        for key in ("sqlite", "event_log", "core_projections"):
            if restored[key] != backup_inspection[key]:
                raise IntegrityError(f"restored database readback mismatch: {key}")
        return {
            "status": "restored_verified",
            "database_identity_digest": content_hash(str(target)),
            "source_backup_sha256": str(manifest["backup_sha256"]),
            "sqlite": restored["sqlite"],
            "event_log": restored["event_log"],
            "core_projections": restored["core_projections"],
            "verification": {
                "manifest_digest_and_shape": "passed",
                "sqlite_integrity": "passed",
                "event_chain": "passed",
                "core_projection_replay_readback": "passed",
            },
            "recovery_set": dict(manifest["recovery_set"]),
            "claim_boundary": dict(manifest["claim_boundary"]),
        }
    except Exception:
        if target_owner is not None:
            _remove_created_database(target_owner)
        raise
