"""Redacted, machine-readable operator snapshot for one SQLite runtime."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .errors import IntegrityError
from .replay import ProjectionReplayer
from .schema import SCHEMA_VERSION
from .store import SQLiteStore
from .types import content_hash, utc_now


OPERATOR_SNAPSHOT_VERSION = 1
_REQUIRED_TABLES = frozenset(
    {
        "schema_migrations",
        "events",
        "principals",
        "authenticated_sessions",
        "runs",
        "tasks",
        "attempts",
        "workflow_steps",
        "leases",
        "approvals",
        "capability_grants",
        "outbox",
        "effect_receipts",
        "evidence_claims",
        "runtime_observations",
        "negative_results",
        "eval_runs",
        "improvement_proposals",
        "sealed_custody_attestations",
        "integration_items",
    }
)


def _read_only_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        path.as_uri() + "?mode=ro", uri=True, timeout=30, isolation_level=None
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _count(
    connection: sqlite3.Connection,
    table: str,
    where: str = "1=1",
    parameters: tuple[Any, ...] = (),
) -> int:
    return int(
        connection.execute(
            f"SELECT COUNT(*) FROM {table} WHERE {where}", parameters
        ).fetchone()[0]
    )


def _sum(connection: sqlite3.Connection, table: str, expression: str) -> int:
    return int(
        connection.execute(
            f"SELECT COALESCE(SUM({expression}), 0) FROM {table}"
        ).fetchone()[0]
    )


def _group(connection: sqlite3.Connection, table: str, field: str) -> dict[str, int]:
    rows = connection.execute(
        f"SELECT {field}, COUNT(*) AS count FROM {table} GROUP BY {field} ORDER BY {field}"
    ).fetchall()
    return {str(row[field]): int(row["count"]) for row in rows}


def operator_snapshot(database: str | Path) -> dict[str, Any]:
    """Return counts/digests/freshness only; never payload or context content."""

    path = Path(database).expanduser().resolve()
    if not path.is_file():
        raise IntegrityError("operator snapshot requires an existing runtime database")
    store = SQLiteStore(path)
    connection = _read_only_connection(path)
    captured_at = utc_now()
    try:
        connection.execute("BEGIN")
        tables = {
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        missing = sorted(_REQUIRED_TABLES - tables)
        if missing:
            raise IntegrityError(
                "operator snapshot missing runtime tables: " + ", ".join(missing)
            )
        migration = connection.execute(
            "SELECT version, checksum, applied_at FROM schema_migrations ORDER BY version DESC LIMIT 1"
        ).fetchone()
        if migration is None or int(migration["version"]) != SCHEMA_VERSION:
            raise IntegrityError("operator snapshot schema version is unsupported")
        event_count = store.verify_event_chain(connection)
        ProjectionReplayer(store).verify(connection=connection)
        event_head = connection.execute(
            "SELECT seq, event_hash, recorded_at FROM events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        snapshot: dict[str, Any] = {
            "snapshot_version": OPERATOR_SNAPSHOT_VERSION,
            "captured_at": captured_at,
            "database_identity_digest": content_hash(str(path)),
            "mode": "single_host_read_only_snapshot",
            "schema": {
                "version": int(migration["version"]),
                "checksum": str(migration["checksum"]),
                "applied_at": str(migration["applied_at"]),
            },
            "event_log": {
                "chain_verified": True,
                "core_projection_replay_verified": True,
                "count": event_count,
                "head_seq": int(event_head["seq"]) if event_head else None,
                "head_hash": str(event_head["event_hash"]) if event_head else None,
                "head_recorded_at": str(event_head["recorded_at"])
                if event_head
                else None,
            },
            "work": {
                "runs": {
                    "total": _count(connection, "runs"),
                    "by_state": _group(connection, "runs", "loop_state"),
                    "unresolved": _count(
                        connection,
                        "runs",
                        "loop_state != 'delivered'",
                    ),
                    "blocked_for_decision_or_state": _count(
                        connection,
                        "runs",
                        "loop_state IN ('blocked_with_decision', "
                        "'blocked_with_missing_state', 'blocked_with_capability_gap')",
                    ),
                },
                "tasks": {
                    "total": _count(connection, "tasks"),
                    "by_state": _group(connection, "tasks", "state"),
                    "non_terminal": _count(
                        connection,
                        "tasks",
                        "state NOT IN ('delivered', 'failed', 'canceled', 'deleted', 'retired')",
                    ),
                },
                "attempts": {
                    "total": _count(connection, "attempts"),
                    "by_state": _group(connection, "attempts", "state"),
                    "open": _count(connection, "attempts", "ended_at IS NULL"),
                },
                "workflow_steps": {
                    "total": _count(connection, "workflow_steps"),
                    "by_status": _group(connection, "workflow_steps", "status"),
                },
            },
            "leases": {
                "total": _count(connection, "leases"),
                "active": _count(
                    connection,
                    "leases",
                    "released_at IS NULL AND julianday(expires_at) > julianday(?)",
                    (captured_at,),
                ),
                "expired_unreleased": _count(
                    connection,
                    "leases",
                    "released_at IS NULL AND julianday(expires_at) <= julianday(?)",
                    (captured_at,),
                ),
                "released": _count(connection, "leases", "released_at IS NOT NULL"),
            },
            "outbox": {
                "total": _count(connection, "outbox"),
                "by_status": _group(connection, "outbox", "status"),
                "pending_recovery": _count(
                    connection, "outbox", "status IN ('authorization_pending', 'ready')"
                ),
                "receipts": _count(connection, "effect_receipts"),
            },
            "integration": {
                "total": _count(connection, "integration_items"),
                "by_state": _group(connection, "integration_items", "state"),
                "unresolved": _count(
                    connection,
                    "integration_items",
                    "state NOT IN ('delivered', 'superseded')",
                ),
            },
            "evaluation": {
                "eval_runs": _count(connection, "eval_runs"),
                "eval_by_status": _group(connection, "eval_runs", "status"),
                "eval_by_split": _group(connection, "eval_runs", "dataset_split"),
                "improvements": _count(connection, "improvement_proposals"),
                "improvements_by_state": _group(
                    connection, "improvement_proposals", "state"
                ),
                "sealed_custody_attestations": _count(
                    connection, "sealed_custody_attestations"
                ),
            },
            "approvals_and_grants": {
                "approvals": _count(connection, "approvals"),
                "approvals_by_decision": _group(connection, "approvals", "decision"),
                "pending_approvals": _count(
                    connection, "approvals", "decision = 'pending'"
                ),
                "grants": _count(connection, "capability_grants"),
                "live_unexhausted_grants": _count(
                    connection,
                    "capability_grants",
                    "revoked_at IS NULL AND used_count < max_uses "
                    "AND julianday(expires_at) > julianday(?)",
                    (captured_at,),
                ),
            },
            "evidence": {
                "total": _count(connection, "evidence_claims"),
                "by_state": _group(connection, "evidence_claims", "evidence_state"),
                "by_verdict": _group(
                    connection, "evidence_claims", "evaluator_verdict"
                ),
            },
            "runtime_observations": {
                "total": _count(connection, "runtime_observations"),
                "by_status": _group(connection, "runtime_observations", "status"),
                "fresh": _count(
                    connection,
                    "runtime_observations",
                    "julianday(expires_at) > julianday(?)",
                    (captured_at,),
                ),
                "expired": _count(
                    connection,
                    "runtime_observations",
                    "julianday(expires_at) <= julianday(?)",
                    (captured_at,),
                ),
            },
            "negative_results": {
                "unique": _count(connection, "negative_results"),
                "recurrences": _sum(connection, "negative_results", "recurrence_count"),
                "by_severity": _group(connection, "negative_results", "severity"),
            },
            "identity": {
                "principals": _count(connection, "principals"),
                "enabled_principals": _count(connection, "principals", "enabled = 1"),
                "live_sessions": _count(
                    connection,
                    "authenticated_sessions",
                    "revoked_at IS NULL AND julianday(expires_at) > julianday(?)",
                    (captured_at,),
                ),
            },
            "claim_boundary": {
                "evidence_state": "runtime_verification",
                "redaction": "counts_digests_freshness_only",
                "non_claims": [
                    "runtime_process_health",
                    "provider_health",
                    "provider_smoke",
                    "human_acceptance",
                    "business_validation",
                    "production_readiness",
                ],
            },
        }
        connection.commit()
        return snapshot
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()
