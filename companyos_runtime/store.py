"""Transactional SQLite store with an append-only, hash-chained event log."""

from __future__ import annotations

import sqlite3
import uuid
import hashlib
import hmac
import os
import re
import threading
import weakref
from contextlib import contextmanager
from dataclasses import dataclass, field
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
_PROTECTED_EVENT_HANDLERS: dict[tuple[str, str], frozenset[str]] = {
    ("approval", "approval_decided"): frozenset({"policy_engine"}),
    ("artifact", "artifact_registered"): frozenset({"evidence_registry"}),
    ("evidence", "evidence_claim_recorded"): frozenset({"evidence_registry"}),
    ("eval", "eval_recorded"): frozenset({"evaluation_registry"}),
    ("improvement", "improvement_proposed"): frozenset({"evaluation_registry"}),
    ("improvement", "improvement_eval_attached"): frozenset({"evaluation_registry"}),
    ("improvement", "improvement_promoted"): frozenset({"evaluation_registry"}),
    ("sealed_custody", "sealed_custody_attested"): frozenset({"evaluation_registry"}),
}
_PROTECTED_AGGREGATES = frozenset(
    aggregate_type for aggregate_type, _ in _PROTECTED_EVENT_HANDLERS
)
_PROTECTED_AUTH_CONTEXT_FIELDS = frozenset(
    {
        "handler",
        "handler_binding_id",
        "handler_config_digest",
        "protected_event",
        "command_authority_version",
    }
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


@dataclass(frozen=True)
class _CommandAuthorityBinding:
    handler: str
    owner: weakref.ReferenceType[Any]
    authority_kind: str
    binding_id: str
    config_digest: str


@dataclass
class _AuthorityDomain:
    """Process-local trust domain shared by every store object for one DB path."""

    command_authorities: dict[object, _CommandAuthorityBinding] = field(
        default_factory=dict
    )
    protected_handler_configs: dict[str, str] = field(default_factory=dict)
    protected_runtime_types: dict[str, tuple[type[Any], ...]] = field(
        default_factory=dict
    )
    lock: Any = field(default_factory=threading.RLock)


_AUTHORITY_DOMAINS: weakref.WeakValueDictionary[str, _AuthorityDomain] = (
    weakref.WeakValueDictionary()
)
_AUTHORITY_DOMAINS_LOCK = threading.RLock()
_EVENT_INSERT_FUNCTION = "companyos_event_insert_authorized"
_EVENT_INSERT_TRIGGER = "events_authorized_insert"
_CONNECTION_CONTROL_AUTHORITY = object()
_EVENT_INSERT_GUARDS: weakref.WeakKeyDictionary[Any, _EventInsertGuard]
_EVENT_INSERT_GUARDS = weakref.WeakKeyDictionary()
_EVENT_INSERT_GUARDS_LOCK = threading.RLock()


def _authority_domain(path: Path) -> _AuthorityDomain:
    key = os.path.normcase(str(path))
    with _AUTHORITY_DOMAINS_LOCK:
        domain = _AUTHORITY_DOMAINS.get(key)
        if domain is None:
            domain = _AuthorityDomain()
            _AUTHORITY_DOMAINS[key] = domain
        return domain


@dataclass
class _EventInsertGuard:
    pending: tuple[str, str] | None = None

    @property
    def armed(self) -> bool:
        return self.pending is not None

    def authorize(self, event_id: Any, event_hash: Any) -> int:
        expected = self.pending
        self.pending = None
        if (
            expected is None
            or not isinstance(event_id, str)
            or not isinstance(event_hash, str)
        ):
            return 0
        return int(
            hmac.compare_digest(expected[0], event_id)
            and hmac.compare_digest(expected[1], event_hash)
        )


class _StoreConnection(sqlite3.Connection):
    """Connection whose event-insert gate is controlled only by SQLiteStore."""

    def _install_authority_controls(self, authority: object) -> None:
        with _EVENT_INSERT_GUARDS_LOCK:
            already_installed = self in _EVENT_INSERT_GUARDS
        if authority is not _CONNECTION_CONTROL_AUTHORITY or already_installed:
            raise IntegrityError("connection authority controls cannot be replaced")
        guard = _EventInsertGuard()
        with _EVENT_INSERT_GUARDS_LOCK:
            _EVENT_INSERT_GUARDS[self] = guard

        def authorizer(
            action: int,
            arg1: str | None,
            arg2: str | None,
            database: str | None,
            source: str | None,
        ) -> int:
            del arg2, database, source
            name = (arg1 or "").casefold()
            if action == sqlite3.SQLITE_INSERT and name == "events" and not guard.armed:
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_DROP_TRIGGER and name == _EVENT_INSERT_TRIGGER:
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_PRAGMA and name == "writable_schema":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        sqlite3.Connection.create_function(
            self,
            _EVENT_INSERT_FUNCTION,
            2,
            guard.authorize,
            deterministic=False,
        )
        sqlite3.Connection.set_authorizer(self, authorizer)

    def _arm_event_insert(
        self, authority: object, *, event_id: str, event_hash: str
    ) -> None:
        if authority is not _CONNECTION_CONTROL_AUTHORITY:
            raise IntegrityError("event insert authority is invalid")
        with _EVENT_INSERT_GUARDS_LOCK:
            guard = _EVENT_INSERT_GUARDS.get(self)
        if guard is None:
            raise IntegrityError("event insert guard is not installed")
        if guard.pending is not None:
            raise IntegrityError("event insert authority is already armed")
        guard.pending = (event_id, event_hash)

    def _clear_event_insert(self, authority: object) -> None:
        if authority is not _CONNECTION_CONTROL_AUTHORITY:
            raise IntegrityError("event insert authority is invalid")
        with _EVENT_INSERT_GUARDS_LOCK:
            guard = _EVENT_INSERT_GUARDS.get(self)
        if guard is None:
            raise IntegrityError("event insert guard is not installed")
        guard.pending = None

    def create_function(
        self,
        name: str,
        narg: int,
        func: Any,
        *,
        deterministic: bool = False,
    ) -> None:
        with _EVENT_INSERT_GUARDS_LOCK:
            controls_locked = self in _EVENT_INSERT_GUARDS
        if controls_locked and name.casefold() == _EVENT_INSERT_FUNCTION:
            raise IntegrityError("reserved event authority function cannot be replaced")
        super().create_function(name, narg, func, deterministic=deterministic)

    def set_authorizer(self, authorizer_callback: Any) -> None:
        with _EVENT_INSERT_GUARDS_LOCK:
            controls_locked = self in _EVENT_INSERT_GUARDS
        if controls_locked:
            raise IntegrityError("event authority authorizer cannot be replaced")
        super().set_authorizer(authorizer_callback)


def protected_authority_config_digest(
    handler: str, config: Mapping[str, Any] | None = None
) -> str:
    """Canonical digest for a protected event handler's trust configuration."""

    return content_hash(
        {
            "authority_contract": "protected-command-v1",
            "handler": handler,
            "config": dict(config or {}),
        }
    )


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
        self.__authority_domain = _authority_domain(self.path)
        self.__command_authorities = self.__authority_domain.command_authorities

    def _prune_dead_command_authorities(self) -> None:
        dead = [
            authority
            for authority, binding in self.__command_authorities.items()
            if binding.owner() is None
        ]
        for authority in dead:
            del self.__command_authorities[authority]

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
        with self.__authority_domain.lock:
            self._prune_dead_command_authorities()
            if any(
                binding.owner() is owner
                for binding in self.__command_authorities.values()
            ):
                raise IntegrityError("core command handler already has bound authority")
            authority = _CoreCommandAuthority()
            self.__command_authorities[authority] = _CommandAuthorityBinding(
                handler=handler,
                owner=weakref.ref(owner),
                authority_kind="core",
                binding_id=str(uuid.uuid4()),
                config_digest=content_hash(
                    {
                        "authority_kind": "core",
                        "handler": handler,
                        "version": _CORE_AUTHORITY_VERSION,
                    }
                ),
            )
            return authority

    def _bind_protected_command_authority(
        self,
        owner: object,
        handler: str,
        *,
        config_digest: str,
        runtime_components: tuple[object, ...] = (),
    ) -> object:
        """Bind a protected event capability to one exact trusted service.

        The binding is intentionally in-process and non-serializable. Persisted
        metadata identifies the handler/config that exercised it; hostile
        reflection or monkeypatching inside this interpreter remains in the TCB.
        """

        expected_type: type[Any]
        if handler == "policy_engine":
            from .policy import PolicyEngine

            expected_type = PolicyEngine
        elif handler == "evidence_registry":
            from .evidence import EvidenceRegistry

            expected_type = EvidenceRegistry
        elif handler == "evaluation_registry":
            from .evaluation import EvaluationRegistry

            expected_type = EvaluationRegistry
        else:
            raise IntegrityError(f"unsupported protected command handler: {handler}")
        if type(owner) is not expected_type:
            raise IntegrityError(
                f"protected command authority cannot bind untrusted handler: {handler}"
            )
        if not isinstance(config_digest, str) or not re.fullmatch(
            r"[0-9a-f]{64}", config_digest
        ):
            raise IntegrityError("protected handler config digest is invalid")
        runtime_types = tuple(type(component) for component in runtime_components)
        with self.__authority_domain.lock:
            self._prune_dead_command_authorities()
            if any(
                binding.owner() is owner
                for binding in self.__command_authorities.values()
            ):
                raise IntegrityError(
                    "trusted command handler already has bound authority"
                )
            live_same_handler = any(
                binding.authority_kind == "protected"
                and binding.handler == handler
                and binding.owner() is not None
                for binding in self.__command_authorities.values()
            )
            if handler == "evaluation_registry" and live_same_handler:
                raise IntegrityError(
                    "evaluation registry authority is already bound for this database"
                )
            pinned_config = self.__authority_domain.protected_handler_configs.get(
                handler
            )
            if pinned_config is not None and pinned_config != config_digest:
                raise IntegrityError(
                    f"protected handler configuration drift: {handler}"
                )
            pinned_types = self.__authority_domain.protected_runtime_types.get(handler)
            if pinned_types is not None and pinned_types != runtime_types:
                raise IntegrityError(
                    f"protected handler implementation drift: {handler}"
                )
            self.__authority_domain.protected_handler_configs[handler] = config_digest
            self.__authority_domain.protected_runtime_types[handler] = runtime_types
            authority = _CoreCommandAuthority()
            self.__command_authorities[authority] = _CommandAuthorityBinding(
                handler=handler,
                owner=weakref.ref(owner),
                authority_kind="protected",
                binding_id=str(uuid.uuid4()),
                config_digest=config_digest,
            )
            return authority

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            self.path,
            timeout=30,
            isolation_level=None,
            factory=_StoreConnection,
            cached_statements=0,
        )
        if not isinstance(connection, _StoreConnection):  # pragma: no cover
            raise IntegrityError("store connection factory is invalid")
        connection._install_authority_controls(_CONNECTION_CONTROL_AUTHORITY)
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
        command_owner: object | None = None,
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
        elif aggregate_type in _PROTECTED_AGGREGATES:
            (
                handler,
                handler_binding_id,
                handler_config_digest,
            ) = self._authorize_protected_event(
                aggregate_type=aggregate_type,
                event_type=event_type,
                command_authority=command_authority,
                command_owner=command_owner,
            )
            reserved = _PROTECTED_AUTH_CONTEXT_FIELDS.intersection(normalized_auth)
            if reserved:
                raise IntegrityError(
                    "protected event authority metadata is store-owned: "
                    f"{sorted(reserved)}"
                )
            normalized_auth.update(
                {
                    "handler": handler,
                    "handler_binding_id": handler_binding_id,
                    "handler_config_digest": handler_config_digest,
                    "protected_event": f"{aggregate_type}/{event_type}",
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
        if not isinstance(connection, _StoreConnection):
            raise IntegrityError("event append requires a store-managed connection")
        connection._arm_event_insert(
            _CONNECTION_CONTROL_AUTHORITY,
            event_id=event_id,
            event_hash=event_hash,
        )
        try:
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
        finally:
            connection._clear_event_insert(_CONNECTION_CONTROL_AUTHORITY)
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
        if (
            authority_record is None
            or authority_record.owner() is None
            or authority_record.authority_kind != "core"
        ):
            raise IntegrityError("core event requires opaque command authority")
        handler = authority_record.handler
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

    def _authorize_protected_event(
        self,
        *,
        aggregate_type: str,
        event_type: str,
        command_authority: object | None,
        command_owner: object | None,
    ) -> tuple[str, str, str]:
        handlers = _PROTECTED_EVENT_HANDLERS.get((aggregate_type, event_type))
        if handlers is None:
            raise IntegrityError(
                f"unsupported protected event: {aggregate_type}/{event_type}"
            )
        try:
            binding = self.__command_authorities.get(command_authority)
        except TypeError:
            binding = None
        if (
            binding is None
            or binding.owner() is None
            or binding.owner() is not command_owner
            or binding.authority_kind != "protected"
            or binding.handler not in handlers
        ):
            raise IntegrityError("protected event requires opaque command authority")
        return binding.handler, binding.binding_id, binding.config_digest

    @staticmethod
    def _verify_protected_event_authority(
        event: Mapping[str, Any],
        *,
        expected_handler: str,
        expected_config_digest: str,
    ) -> str:
        try:
            auth = __import__("json").loads(event["auth_context_json"])
            aggregate_type = str(event["aggregate_type"])
            event_type = str(event["event_type"])
        except (KeyError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "protected event authority metadata is malformed"
            ) from exc
        handlers = _PROTECTED_EVENT_HANDLERS.get((aggregate_type, event_type))
        if (
            not isinstance(auth, dict)
            or set(auth) != _PROTECTED_AUTH_CONTEXT_FIELDS
            or handlers is None
            or expected_handler not in handlers
            or auth.get("handler") != expected_handler
            or auth.get("handler_config_digest") != expected_config_digest
            or auth.get("command_authority_version") != _CORE_AUTHORITY_VERSION
            or auth.get("protected_event") != f"{aggregate_type}/{event_type}"
            or not isinstance(auth.get("handler_binding_id"), str)
            or not auth["handler_binding_id"]
        ):
            raise IntegrityError("protected event authority metadata is invalid")
        return str(auth["handler_binding_id"])

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
                elif row["aggregate_type"] in _PROTECTED_AGGREGATES:
                    auth = envelope["auth_context"]
                    handlers = _PROTECTED_EVENT_HANDLERS.get(
                        (row["aggregate_type"], row["event_type"])
                    )
                    if (
                        not isinstance(auth, dict)
                        or set(auth) != _PROTECTED_AUTH_CONTEXT_FIELDS
                        or handlers is None
                        or auth.get("handler") not in handlers
                        or auth.get("command_authority_version")
                        != _CORE_AUTHORITY_VERSION
                        or auth.get("protected_event")
                        != f"{row['aggregate_type']}/{row['event_type']}"
                        or not isinstance(auth.get("handler_binding_id"), str)
                        or not auth["handler_binding_id"]
                        or not isinstance(auth.get("handler_config_digest"), str)
                        or re.fullmatch(r"[0-9a-f]{64}", auth["handler_config_digest"])
                        is None
                    ):
                        raise IntegrityError(
                            "protected event authority metadata invalid at "
                            f"seq {row['seq']}"
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
