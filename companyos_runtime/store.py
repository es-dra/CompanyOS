"""Transactional SQLite store with an append-only, hash-chained event log."""

from __future__ import annotations

import sqlite3
import uuid
import hashlib
import hmac
import weakref
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

from .errors import IntegrityError
from .schema import DDL, SCHEMA_VERSION
from .types import LoopEvent, TaskState, canonical_json, content_hash, utc_now


_CORE_HANDLERS = {
    "goal": {"runtime_kernel"},
    "run": {"runtime_kernel"},
    "task": {"runtime_kernel", "task_scheduler"},
}
_CORE_AUTHORITY_VERSION = "opaque-command-v1"
_CORE_AUTH_CONTEXT_FIELDS = frozenset(
    {"handler", "authorized_role", "session_id", "command_authority_version"}
)


class _CoreCommandAuthority:
    """Opaque in-process capability used only by trusted command handlers.

    Object identity prevents an ordinary caller from recreating authority by
    copying serialized ``auth_context`` values.  This is deliberately an
    in-process API boundary, not isolation from hostile code that can inspect
    or monkeypatch private module state; such code is inside the Python
    process's trusted computing base.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - defensive diagnostics only
        return "<opaque core command authority>"


_RUN_EVENT_ROLES = {
    LoopEvent.OWNER_INTENT_RECEIVED.value: {"owner", "system"},
    LoopEvent.GOAL_COMPILED.value: {"system"},
    LoopEvent.RUN_READY.value: {"system"},
    LoopEvent.TASK_STARTED.value: {"worker", "system"},
    LoopEvent.HUMAN_APPROVAL_REQUESTED.value: {"worker", "system"},
    LoopEvent.HUMAN_APPROVAL_RECEIVED.value: {"owner", "system"},
    LoopEvent.EVIDENCE_SUBMITTED.value: {"worker", "system"},
    LoopEvent.EVALUATOR_VERDICT_RECEIVED.value: {"evaluator"},
    LoopEvent.CI_CHECK_STARTED.value: {"release", "system"},
    LoopEvent.CI_CHECK_COMPLETED.value: {"release", "system"},
    LoopEvent.DEPLOY_DIRECTORY_UPDATED.value: {"release"},
    LoopEvent.SERVICE_RESTART_ATTEMPTED.value: {"release"},
    LoopEvent.RUNTIME_FRESHNESS_VERIFIED.value: {"observer"},
    LoopEvent.RUNTIME_DRIFT_DETECTED.value: {"observer", "system"},
    LoopEvent.DELIVERY_CONFIRMED.value: {"release"},
    LoopEvent.IMPROVEMENT_REQUESTED.value: {"owner", "system"},
    LoopEvent.RESUME_REQUESTED.value: {"owner", "system"},
    LoopEvent.CAPABILITY_GAP_DETECTED.value: {"system"},
    LoopEvent.MISSING_STATE_DETECTED.value: {"system"},
    LoopEvent.CIRCUIT_BREAKER_TRIGGERED.value: {"worker", "system"},
}
_TASK_TARGET_ROLES = {
    TaskState.LEASED.value: {"worker", "system"},
    TaskState.RUNNING.value: {"worker", "system"},
    TaskState.EVIDENCE_PENDING.value: {"worker", "system"},
    TaskState.EVALUATOR_PENDING.value: {"evaluator", "system"},
    TaskState.INTEGRATION_PENDING.value: {"evaluator", "system"},
    TaskState.DELIVERED.value: {"release"},
    TaskState.RETRY_PENDING.value: {"worker", "system"},
    TaskState.FAILED.value: {"worker", "system"},
    TaskState.BLOCKED.value: {"owner", "system"},
    TaskState.CANCELED.value: {"owner", "system"},
    TaskState.DELETED.value: {"owner", "system"},
    TaskState.RETIRED.value: {"owner", "system"},
    TaskState.SUSPENDED.value: {"owner", "worker", "system"},
    TaskState.READY.value: {"system"},
}


class SQLiteStore:
    """Single-host durable store.

    SQLite WAL provides process-safe local durability. It is deliberately not a
    multi-host coordination claim and must not live on a network share.
    """

    def __init__(self, path: str | Path):
        raw = str(path)
        if raw == ":memory:":
            raise ValueError(
                "use a temporary file; per-connection :memory: databases are unsupported"
            )
        if raw.startswith(("\\\\", "//")):
            raise ValueError(
                "SQLite runtime state must not be placed on a network/UNC share"
            )
        self.path = Path(path).expanduser().resolve()
        self.__command_authorities: dict[
            object, tuple[str, weakref.ReferenceType[Any]]
        ] = {}

    def _bind_core_command_authority(self, owner: object, handler: str) -> object:
        """Bind one opaque capability to an exact trusted service instance.

        The returned token is retained by that service and is not exposed by a
        public store API.  Exact-type checks keep ordinary callers and lookalike
        classes from registering themselves as core handlers.  Reflection or
        monkeypatching inside this interpreter remains part of the documented
        in-process TCB.
        """

        expected_type: type[Any]
        if handler == "runtime_kernel":
            from .kernel import RuntimeKernel

            expected_type = RuntimeKernel
        elif handler == "task_scheduler":
            from .scheduler import TaskScheduler

            expected_type = TaskScheduler
        else:
            raise IntegrityError(f"unsupported core command handler: {handler}")
        if type(owner) is not expected_type:
            raise IntegrityError(
                f"core command authority cannot bind untrusted handler: {handler}"
            )
        if any(
            reference() is owner for _, reference in self.__command_authorities.values()
        ):
            raise IntegrityError("core command handler already has bound authority")
        authority = _CoreCommandAuthority()
        self.__command_authorities[authority] = (handler, weakref.ref(owner))
        return authority

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        connection = self.connect()
        checksum = content_hash(DDL)
        try:
            has_migrations = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
            ).fetchone()
            if has_migrations:
                existing = connection.execute(
                    "SELECT checksum FROM schema_migrations WHERE version = ?",
                    (SCHEMA_VERSION,),
                ).fetchone()
                if existing and existing["checksum"] != checksum:
                    raise IntegrityError(
                        "schema migration checksum changed after application"
                    )
            connection.executescript("BEGIN IMMEDIATE;\n" + DDL + "\nCOMMIT;")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at, checksum) VALUES (?, ?, ?)",
                (SCHEMA_VERSION, utc_now(), checksum),
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def append_event(
        self,
        connection: sqlite3.Connection,
        *,
        aggregate_type: str,
        aggregate_id: str,
        expected_version: int,
        project_id: str,
        event_type: str,
        actor: str,
        command_id: str,
        correlation_id: str,
        policy_version: str,
        payload: Mapping[str, Any],
        auth_context: Mapping[str, Any] | None = None,
        auth_session: Any | None = None,
        command_authority: object | None = None,
        run_id: str | None = None,
        task_id: str | None = None,
        idempotency_key: str | None = None,
        causation_id: str | None = None,
        confidentiality: str = "internal",
        occurred_at: str | None = None,
    ) -> dict[str, Any]:
        normalized_auth = dict(auth_context or {})
        if aggregate_type in _CORE_HANDLERS:
            handler, authorized_role, verified_session_id = self._authorize_core_event(
                connection,
                aggregate_type=aggregate_type,
                event_type=event_type,
                actor=actor,
                payload=payload,
                auth_session=auth_session,
                command_authority=command_authority,
            )
            reserved = _CORE_AUTH_CONTEXT_FIELDS.intersection(normalized_auth)
            if reserved:
                raise IntegrityError(
                    f"core event authority metadata is store-owned: {sorted(reserved)}"
                )
            normalized_auth.update(
                {
                    "handler": handler,
                    "authorized_role": authorized_role,
                    "session_id": verified_session_id,
                    "command_authority_version": _CORE_AUTHORITY_VERSION,
                }
            )
        head = connection.execute(
            "SELECT COALESCE(MAX(aggregate_version), 0) AS version FROM events "
            "WHERE aggregate_type = ? AND aggregate_id = ?",
            (aggregate_type, aggregate_id),
        ).fetchone()
        current_version = int(head["version"])
        if current_version != expected_version:
            raise IntegrityError(
                f"aggregate version conflict for {aggregate_type}/{aggregate_id}: "
                f"expected {expected_version}, found {current_version}"
            )
        if causation_id is not None:
            caused_by = connection.execute(
                "SELECT seq FROM events WHERE event_id = ?", (causation_id,)
            ).fetchone()
            if caused_by is None:
                raise IntegrityError(f"causation event does not exist: {causation_id}")
        global_head = connection.execute(
            "SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        previous_hash = global_head["event_hash"] if global_head else "GENESIS"
        event_id = str(uuid.uuid4())
        recorded_at = utc_now()
        occurred = occurred_at or recorded_at
        payload_json = canonical_json(dict(payload))
        envelope = {
            "event_id": event_id,
            "aggregate_type": aggregate_type,
            "aggregate_id": aggregate_id,
            "aggregate_version": current_version + 1,
            "project_id": project_id,
            "run_id": run_id,
            "task_id": task_id,
            "event_type": event_type,
            "schema_version": 1,
            "actor": actor,
            "auth_context": normalized_auth,
            "command_id": command_id,
            "idempotency_key": idempotency_key,
            "correlation_id": correlation_id,
            "causation_id": causation_id,
            "policy_version": policy_version,
            "occurred_at": occurred,
            "recorded_at": recorded_at,
            "confidentiality": confidentiality,
            "payload_digest": content_hash(payload_json),
            "previous_event_hash": previous_hash,
        }
        event_hash = content_hash(previous_hash + canonical_json(envelope))
        connection.execute(
            """
            INSERT INTO events(
                event_id, aggregate_type, aggregate_id, aggregate_version,
                project_id, run_id, task_id, event_type, schema_version, actor,
                auth_context_json, command_id, idempotency_key, correlation_id,
                causation_id, policy_version, occurred_at, recorded_at,
                confidentiality, payload_json, payload_digest,
                previous_event_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                aggregate_type,
                aggregate_id,
                current_version + 1,
                project_id,
                run_id,
                task_id,
                event_type,
                1,
                actor,
                canonical_json(normalized_auth),
                command_id,
                idempotency_key,
                correlation_id,
                causation_id,
                policy_version,
                occurred,
                recorded_at,
                confidentiality,
                payload_json,
                envelope["payload_digest"],
                previous_hash,
                event_hash,
            ),
        )
        envelope["event_hash"] = event_hash
        envelope["payload"] = dict(payload)
        return envelope

    @staticmethod
    def _core_roles(
        aggregate_type: str,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        handler: str | None = None,
    ) -> set[str]:
        if aggregate_type == "goal":
            if event_type != "goal_created":
                raise IntegrityError(f"unsupported goal event type: {event_type}")
            return {"owner"}
        if aggregate_type == "run":
            roles = _RUN_EVENT_ROLES.get(event_type)
            if roles is None:
                raise IntegrityError(f"unsupported run event type: {event_type}")
            return roles
        if event_type == "task_added":
            return {"owner", "system"}
        if event_type != "task_state_changed":
            raise IntegrityError(f"unsupported task event type: {event_type}")
        target = payload.get("target")
        roles = _TASK_TARGET_ROLES.get(str(target))
        if roles is None:
            raise IntegrityError(f"unsupported task transition target: {target}")
        resolved = set(roles)
        if handler == "runtime_kernel" and target in {
            TaskState.LEASED.value,
            TaskState.READY.value,
        }:
            resolved.add("owner")
        return resolved

    def _authorize_core_event(
        self,
        connection: sqlite3.Connection,
        *,
        aggregate_type: str,
        event_type: str,
        actor: str,
        payload: Mapping[str, Any],
        auth_session: Any | None,
        command_authority: object | None,
    ) -> tuple[str, str, str]:
        try:
            authority_record = self.__command_authorities.get(command_authority)
        except TypeError:
            authority_record = None
        if authority_record is None or authority_record[1]() is None:
            raise IntegrityError("core event requires opaque command authority")
        handler = authority_record[0]
        if not self._handler_supports_event(handler, aggregate_type, event_type):
            raise IntegrityError(
                f"core command handler {handler} cannot append "
                f"{aggregate_type}/{event_type}"
            )
        try:
            session_id = object.__getattribute__(auth_session, "_session_id")
            session_secret = object.__getattribute__(auth_session, "_session_secret")
            session_principal_id = object.__getattribute__(
                auth_session, "_principal_id"
            )
        except (AttributeError, TypeError) as exc:
            raise IntegrityError(
                "core event requires an authenticated bearer session"
            ) from exc
        if (
            not isinstance(session_id, str)
            or not session_id
            or not isinstance(session_secret, bytes)
            or session_principal_id != actor
        ):
            raise IntegrityError("core event bearer session is malformed")
        allowed_roles = self._core_roles(
            aggregate_type, event_type, payload, handler=handler
        )
        placeholders = ",".join("?" for _ in allowed_roles)
        row = connection.execute(
            f"""
            SELECT r.role, s.session_token_hash
            FROM authenticated_sessions AS s
            JOIN principals AS p ON p.principal_id = s.principal_id
            JOIN principal_roles AS r ON r.principal_id = p.principal_id
            WHERE s.session_id = ? AND s.principal_id = ?
              AND s.revoked_at IS NULL AND p.enabled = 1
              AND s.credential_version = p.credential_version
              AND julianday(s.issued_at) <= julianday('now')
              AND julianday(s.expires_at) > julianday('now')
              AND r.role IN ({placeholders})
            ORDER BY r.role LIMIT 1
            """,
            (session_id, actor, *sorted(allowed_roles)),
        ).fetchone()
        bearer_digest = hashlib.sha256(session_secret).digest()
        if row is None or not hmac.compare_digest(
            bearer_digest, bytes(row["session_token_hash"])
        ):
            raise IntegrityError("core event actor/session/role is not authorized")
        return handler, str(row["role"]), session_id

    @staticmethod
    def _handler_supports_event(
        handler: str, aggregate_type: str, event_type: str
    ) -> bool:
        if handler == "runtime_kernel":
            return aggregate_type in _CORE_HANDLERS
        return (
            handler == "task_scheduler"
            and aggregate_type == "task"
            and event_type == "task_state_changed"
        )

    def get_idempotent_result(
        self,
        connection: sqlite3.Connection,
        *,
        project_id: str,
        scope: str,
        key: str,
        payload_digest: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT payload_digest, result_json FROM idempotency_records "
            "WHERE project_id = ? AND scope = ? AND idempotency_key = ?",
            (project_id, scope, key),
        ).fetchone()
        if row is None:
            return None
        if row["payload_digest"] != payload_digest:
            raise IntegrityError(
                f"idempotency key reused with different payload: {scope}/{key}"
            )
        import json

        return json.loads(row["result_json"])

    def save_idempotent_result(
        self,
        connection: sqlite3.Connection,
        *,
        project_id: str,
        scope: str,
        key: str,
        payload_digest: str,
        result: Mapping[str, Any],
        event_id: str,
    ) -> None:
        connection.execute(
            "INSERT INTO idempotency_records(project_id, scope, idempotency_key, "
            "payload_digest, result_json, event_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                project_id,
                scope,
                key,
                payload_digest,
                canonical_json(dict(result)),
                event_id,
                utc_now(),
            ),
        )

    def verify_event_chain(self, connection: sqlite3.Connection | None = None) -> int:
        """Verify the global chain in one caller-selected database snapshot.

        Passing an active connection lets repair/verification bind chain
        validation, replay, and projection comparison to the same transaction.
        The default keeps the public read-only convenience API unchanged.
        """

        owns_connection = connection is None
        if connection is None:
            connection = self.connect()
        try:
            rows = connection.execute("SELECT * FROM events ORDER BY seq").fetchall()
            previous_hash = "GENESIS"
            for row in rows:
                if row["previous_event_hash"] != previous_hash:
                    raise IntegrityError(f"event chain break at seq {row['seq']}")
                envelope = {
                    "event_id": row["event_id"],
                    "aggregate_type": row["aggregate_type"],
                    "aggregate_id": row["aggregate_id"],
                    "aggregate_version": row["aggregate_version"],
                    "project_id": row["project_id"],
                    "run_id": row["run_id"],
                    "task_id": row["task_id"],
                    "event_type": row["event_type"],
                    "schema_version": row["schema_version"],
                    "actor": row["actor"],
                    "auth_context": __import__("json").loads(row["auth_context_json"]),
                    "command_id": row["command_id"],
                    "idempotency_key": row["idempotency_key"],
                    "correlation_id": row["correlation_id"],
                    "causation_id": row["causation_id"],
                    "policy_version": row["policy_version"],
                    "occurred_at": row["occurred_at"],
                    "recorded_at": row["recorded_at"],
                    "confidentiality": row["confidentiality"],
                    "payload_digest": row["payload_digest"],
                    "previous_event_hash": row["previous_event_hash"],
                }
                if (
                    content_hash(previous_hash + canonical_json(envelope))
                    != row["event_hash"]
                ):
                    raise IntegrityError(f"event hash mismatch at seq {row['seq']}")
                if content_hash(row["payload_json"]) != row["payload_digest"]:
                    raise IntegrityError(
                        f"event payload digest mismatch at seq {row['seq']}"
                    )
                if row["aggregate_type"] in _CORE_HANDLERS:
                    auth = envelope["auth_context"]
                    payload = __import__("json").loads(row["payload_json"])
                    if not isinstance(auth, dict):
                        raise IntegrityError(
                            f"core event authority metadata invalid at seq {row['seq']}"
                        )
                    allowed_roles = self._core_roles(
                        row["aggregate_type"],
                        row["event_type"],
                        payload,
                        handler=str(auth.get("handler")),
                    )
                    if (
                        auth.get("command_authority_version") != _CORE_AUTHORITY_VERSION
                        or auth.get("handler")
                        not in _CORE_HANDLERS[row["aggregate_type"]]
                        or not self._handler_supports_event(
                            str(auth.get("handler")),
                            row["aggregate_type"],
                            row["event_type"],
                        )
                        or auth.get("authorized_role") not in allowed_roles
                    ):
                        raise IntegrityError(
                            f"core event authority metadata invalid at seq {row['seq']}"
                        )
                    session = connection.execute(
                        "SELECT * FROM authenticated_sessions WHERE session_id = ? "
                        "AND principal_id = ?",
                        (auth.get("session_id"), row["actor"]),
                    ).fetchone()
                    if session is None:
                        raise IntegrityError(
                            f"core event session missing at seq {row['seq']}"
                        )
                    valid_at_event = connection.execute(
                        "SELECT julianday(?) >= julianday(?) "
                        "AND julianday(?) < julianday(?) "
                        "AND (? IS NULL OR julianday(?) >= julianday(?))",
                        (
                            row["occurred_at"],
                            session["issued_at"],
                            row["occurred_at"],
                            session["expires_at"],
                            session["revoked_at"],
                            session["revoked_at"],
                            row["occurred_at"],
                        ),
                    ).fetchone()[0]
                    if valid_at_event != 1:
                        raise IntegrityError(
                            f"core event session was not valid at seq {row['seq']}"
                        )
                previous_hash = row["event_hash"]
            return len(rows)
        finally:
            if owns_connection:
                connection.close()

    def query(self, sql: str, parameters: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        connection = self.connect()
        try:
            return [dict(row) for row in connection.execute(sql, parameters).fetchall()]
        finally:
            connection.close()
