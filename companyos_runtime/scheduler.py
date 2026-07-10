"""Bounded single-host task supervision with retries and abandoned-work recovery."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

from .errors import LeaseError
from .identity import IdentityManager, Role, VerifiedPrincipal
from .state_machine import require_transition
from .store import SQLiteStore
from .types import LoopState, TaskSpec, TaskState, content_hash, utc_now


_EXECUTABLE_RUN_STATES = frozenset({LoopState.READY.value, LoopState.RUNNING.value})


@dataclass(frozen=True)
class TaskClaim:
    task_id: str
    run_id: str
    attempt_id: str
    attempt_number: int
    worker_id: str
    resource_key: str
    fence: int
    expires_at: str


@dataclass(frozen=True)
class FailureOutcome:
    task_id: str
    attempt_id: str
    state: TaskState
    retry_due_at: str | None
    circuit_open: bool
    fingerprint: str


class TaskScheduler:
    """Provides supervision primitives, not an always-on daemon.

    One or more local worker processes may call these methods. SQLite
    ``BEGIN IMMEDIATE`` serializes claims; monotonic fences reject stale
    workers. A production service still needs an external process supervisor.
    """

    def __init__(
        self,
        store: SQLiteStore,
        *,
        policy_version: str = "companyos-policy-v1",
        retry_base_seconds: int = 5,
        retry_max_seconds: int = 300,
        identity: IdentityManager | None = None,
    ):
        if retry_base_seconds < 1 or retry_max_seconds < retry_base_seconds:
            raise ValueError("retry bounds must be positive and ordered")
        self.store = store
        self.__command_authority = store._bind_core_command_authority(
            self, "task_scheduler"
        )
        self.policy_version = policy_version
        self.retry_base_seconds = retry_base_seconds
        self.retry_max_seconds = retry_max_seconds
        self.identity = identity or IdentityManager(store)

    def _worker_id(self, worker: VerifiedPrincipal) -> str:
        return self.identity.require_role(worker, Role.WORKER).principal_id

    def _system_id(self, actor: VerifiedPrincipal) -> str:
        return self.identity.require_role(actor, Role.SYSTEM).principal_id

    @staticmethod
    def _task_resource(task_id: str) -> str:
        return f"task://{task_id}"

    @staticmethod
    def _now(connection: Any) -> str:
        return connection.execute(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
        ).fetchone()[0]

    @staticmethod
    def _expires(connection: Any, seconds: int) -> str:
        return connection.execute(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)", (f"+{seconds} seconds",)
        ).fetchone()[0]

    def _retry_due(self, connection: Any, attempt_number: int) -> str:
        seconds = min(
            self.retry_base_seconds * (2 ** max(attempt_number - 1, 0)),
            self.retry_max_seconds,
        )
        return self._expires(connection, seconds)

    @staticmethod
    def _require_executable_run(connection: Any, row: Mapping[str, Any]) -> None:
        run = connection.execute(
            "SELECT loop_state, project_id, goal_id FROM runs WHERE run_id = ?",
            (row["run_id"],),
        ).fetchone()
        if (
            run is None
            or run["project_id"] != row["project_id"]
            or run["goal_id"] != row["goal_id"]
            or run["loop_state"] != LoopState.RUNNING.value
        ):
            raise LeaseError(f"task parent run is not executable: {row['run_id']}")

    def _transition(
        self,
        connection: Any,
        row: Mapping[str, Any],
        target: TaskState,
        *,
        actor: str,
        reason: str,
        auth_session: VerifiedPrincipal,
    ) -> dict[str, Any]:
        current = TaskState(row["state"])
        require_transition(current, target)
        version = int(row["aggregate_version"])
        self.store.append_event(
            connection,
            aggregate_type="task",
            aggregate_id=row["task_id"],
            expected_version=version,
            project_id=row["project_id"],
            run_id=row["run_id"],
            task_id=row["task_id"],
            event_type="task_state_changed",
            actor=actor,
            auth_session=auth_session,
            command_authority=self.__command_authority,
            command_id=str(uuid.uuid4()),
            correlation_id=row["run_id"] or row["goal_id"],
            policy_version=self.policy_version,
            payload={"from": current.value, "target": target.value, "reason": reason},
        )
        connection.execute(
            "UPDATE tasks SET state = ?, aggregate_version = ?, updated_at = ? WHERE task_id = ?",
            (target.value, version + 1, utc_now(), row["task_id"]),
        )
        updated = dict(row)
        updated["state"] = target.value
        updated["aggregate_version"] = version + 1
        return updated

    def promote_due_retries(
        self, *, project_id: str, actor: VerifiedPrincipal, limit: int = 100
    ) -> int:
        actor_id = self._system_id(actor)
        with self.store.transaction(immediate=True) as connection:
            rows = connection.execute(
                "SELECT t.* FROM tasks AS t JOIN runs AS r ON r.run_id = t.run_id "
                "WHERE t.project_id = ? AND t.state = ? "
                "AND r.project_id = t.project_id AND r.goal_id = t.goal_id "
                "AND r.loop_state IN (?, ?) "
                "AND (t.due_at IS NULL OR julianday(t.due_at) <= julianday('now')) "
                "ORDER BY t.due_at, t.task_id LIMIT ?",
                (
                    project_id,
                    TaskState.RETRY_PENDING.value,
                    LoopState.READY.value,
                    LoopState.RUNNING.value,
                    limit,
                ),
            ).fetchall()
            for row in rows:
                self._transition(
                    connection,
                    row,
                    TaskState.READY,
                    actor=actor_id,
                    reason="retry backoff elapsed",
                    auth_session=actor,
                )
            return len(rows)

    def claim_next(
        self,
        *,
        project_id: str,
        worker: VerifiedPrincipal,
        ttl_seconds: int = 60,
    ) -> TaskClaim | None:
        worker_id = self._worker_id(worker)
        if ttl_seconds < 1:
            raise LeaseError("ttl_seconds must be positive")
        with self.store.transaction(immediate=True) as connection:
            rows = connection.execute(
                "SELECT t.* FROM tasks AS t JOIN runs AS r ON r.run_id = t.run_id "
                "WHERE t.project_id = ? AND t.state = ? "
                "AND r.project_id = t.project_id AND r.goal_id = t.goal_id "
                "AND r.loop_state IN (?, ?) "
                "AND (t.due_at IS NULL OR julianday(t.due_at) <= julianday('now')) "
                "ORDER BY t.due_at, t.created_at, t.task_id",
                (
                    project_id,
                    TaskState.READY.value,
                    LoopState.READY.value,
                    LoopState.RUNNING.value,
                ),
            ).fetchall()
            selected = None
            spec = None
            for row in rows:
                candidate = TaskSpec.from_dict(json.loads(row["spec_json"]))
                if (
                    int(row["attempt_count"]) < candidate.max_attempts
                    and row["run_id"] is not None
                ):
                    selected = row
                    spec = candidate
                    break
            if selected is None or spec is None:
                return None
            resource = self._task_resource(selected["task_id"])
            existing = connection.execute(
                "SELECT * FROM leases WHERE resource_key = ?", (resource,)
            ).fetchone()
            if existing is not None:
                active = connection.execute(
                    "SELECT released_at IS NULL AND julianday(expires_at) > julianday('now') "
                    "FROM leases WHERE resource_key = ?",
                    (resource,),
                ).fetchone()[0]
                if active == 1:
                    return None
                fence = int(existing["fence"]) + 1
            else:
                fence = 1
            issued_at = self._now(connection)
            expires_at = self._expires(connection, ttl_seconds)
            connection.execute(
                """
                INSERT INTO leases(resource_key, project_id, task_id, holder, fence, issued_at, expires_at, released_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(resource_key) DO UPDATE SET project_id=excluded.project_id,
                  task_id=excluded.task_id, holder=excluded.holder, fence=excluded.fence,
                  issued_at=excluded.issued_at, expires_at=excluded.expires_at, released_at=NULL
                """,
                (
                    resource,
                    project_id,
                    selected["task_id"],
                    worker_id,
                    fence,
                    issued_at,
                    expires_at,
                ),
            )
            attempt_number = int(selected["attempt_count"]) + 1
            attempt_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO attempts(attempt_id, task_id, run_id, attempt_number, worker_id, state, started_at) "
                "VALUES (?, ?, ?, ?, ?, 'leased', ?)",
                (
                    attempt_id,
                    selected["task_id"],
                    selected["run_id"],
                    attempt_number,
                    worker_id,
                    issued_at,
                ),
            )
            updated = self._transition(
                connection,
                selected,
                TaskState.LEASED,
                actor=worker_id,
                reason=f"scheduler claim fence {fence}",
                auth_session=worker,
            )
            connection.execute(
                "UPDATE tasks SET attempt_count = ?, due_at = NULL WHERE task_id = ?",
                (attempt_number, updated["task_id"]),
            )
            return TaskClaim(
                task_id=selected["task_id"],
                run_id=selected["run_id"],
                attempt_id=attempt_id,
                attempt_number=attempt_number,
                worker_id=worker_id,
                resource_key=resource,
                fence=fence,
                expires_at=expires_at,
            )

    def start(self, claim: TaskClaim, *, worker: VerifiedPrincipal) -> None:
        worker_id = self._worker_id(worker)
        if worker_id != claim.worker_id:
            raise LeaseError("authenticated worker does not own the task claim")
        with self.store.transaction(immediate=True) as connection:
            self._require_claim(connection, claim)
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (claim.task_id,)
            ).fetchone()
            self._require_executable_run(connection, row)
            self._transition(
                connection,
                row,
                TaskState.RUNNING,
                actor=claim.worker_id,
                reason=f"attempt {claim.attempt_number} started",
                auth_session=worker,
            )
            connection.execute(
                "UPDATE attempts SET state = 'running' WHERE attempt_id = ? AND state = 'leased'",
                (claim.attempt_id,),
            )

    def complete(self, claim: TaskClaim, *, worker: VerifiedPrincipal) -> None:
        worker_id = self._worker_id(worker)
        if worker_id != claim.worker_id:
            raise LeaseError("authenticated worker does not own the task claim")
        with self.store.transaction(immediate=True) as connection:
            self._require_claim(connection, claim)
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (claim.task_id,)
            ).fetchone()
            self._transition(
                connection,
                row,
                TaskState.EVIDENCE_PENDING,
                actor=claim.worker_id,
                reason=f"attempt {claim.attempt_number} completed; evidence pending",
                auth_session=worker,
            )
            now = self._now(connection)
            connection.execute(
                "UPDATE attempts SET state = 'succeeded', ended_at = ? WHERE attempt_id = ?",
                (now, claim.attempt_id),
            )
            connection.execute(
                "UPDATE leases SET released_at = ? WHERE resource_key = ? AND fence = ?",
                (now, claim.resource_key, claim.fence),
            )

    def fail(
        self,
        claim: TaskClaim,
        *,
        worker: VerifiedPrincipal,
        failure_class: str,
        message: str,
        severity: str = "error",
        repair_route: str = "retry_after_backoff",
    ) -> FailureOutcome:
        worker_id = self._worker_id(worker)
        if worker_id != claim.worker_id:
            raise LeaseError("authenticated worker does not own the task claim")
        fingerprint = content_hash({"failure_class": failure_class, "message": message})
        with self.store.transaction(immediate=True) as connection:
            self._require_claim(connection, claim)
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (claim.task_id,)
            ).fetchone()
            spec = TaskSpec.from_dict(json.loads(row["spec_json"]))
            now = self._now(connection)
            failure_id = self._record_negative(
                connection,
                row,
                fingerprint=fingerprint,
                failure_class=failure_class,
                severity=severity,
                repair_route=repair_route,
                now=now,
            )
            row = self._transition(
                connection,
                row,
                TaskState.FAILED,
                actor=claim.worker_id,
                reason=failure_class,
                auth_session=worker,
            )
            circuit_open = int(row["attempt_count"]) >= spec.max_attempts
            retry_due = None
            if not circuit_open:
                row = self._transition(
                    connection,
                    row,
                    TaskState.RETRY_PENDING,
                    actor=worker_id,
                    reason="bounded retry scheduled",
                    auth_session=worker,
                )
                retry_due = self._retry_due(connection, claim.attempt_number)
            connection.execute(
                "UPDATE tasks SET due_at = ?, last_error_fingerprint = ? WHERE task_id = ?",
                (retry_due, fingerprint, claim.task_id),
            )
            connection.execute(
                "UPDATE attempts SET state = 'failed', ended_at = ?, failure_id = ? WHERE attempt_id = ?",
                (now, failure_id, claim.attempt_id),
            )
            connection.execute(
                "UPDATE leases SET released_at = ? WHERE resource_key = ? AND fence = ?",
                (now, claim.resource_key, claim.fence),
            )
            return FailureOutcome(
                task_id=claim.task_id,
                attempt_id=claim.attempt_id,
                state=TaskState(row["state"]),
                retry_due_at=retry_due,
                circuit_open=circuit_open,
                fingerprint=fingerprint,
            )

    def reap_expired(
        self, *, project_id: str, actor: VerifiedPrincipal, limit: int = 100
    ) -> int:
        actor_id = self._system_id(actor)
        with self.store.transaction(immediate=True) as connection:
            rows = connection.execute(
                """
                SELECT t.* FROM tasks AS t
                LEFT JOIN leases AS l ON l.resource_key = 'task://' || t.task_id
                WHERE t.project_id = ? AND t.state IN ('leased', 'running')
                  AND (l.resource_key IS NULL OR l.released_at IS NOT NULL
                    OR julianday(l.expires_at) <= julianday('now'))
                ORDER BY t.updated_at LIMIT ?
                """,
                (project_id, limit),
            ).fetchall()
            now = self._now(connection)
            for original in rows:
                row = original
                spec = TaskSpec.from_dict(json.loads(row["spec_json"]))
                fingerprint = content_hash(
                    {"failure_class": "WorkerLeaseExpired", "task_id": row["task_id"]}
                )
                failure_id = self._record_negative(
                    connection,
                    row,
                    fingerprint=fingerprint,
                    failure_class="WorkerLeaseExpired",
                    severity="error",
                    repair_route="scheduler_reclaim",
                    now=now,
                )
                circuit_open = int(row["attempt_count"]) >= spec.max_attempts
                if TaskState(row["state"]) is TaskState.RUNNING:
                    row = self._transition(
                        connection,
                        row,
                        TaskState.RETRY_PENDING,
                        actor=actor_id,
                        reason="worker lease expired",
                        auth_session=actor,
                    )
                else:
                    row = self._transition(
                        connection,
                        row,
                        TaskState.RETRY_PENDING,
                        actor=actor_id,
                        reason="worker lease expired before start",
                        auth_session=actor,
                    )
                due: str | None = self._retry_due(connection, int(row["attempt_count"]))
                if circuit_open:
                    row = self._transition(
                        connection,
                        row,
                        TaskState.FAILED,
                        actor=actor_id,
                        reason="attempt limit exhausted",
                        auth_session=actor,
                    )
                    due = None
                connection.execute(
                    "UPDATE tasks SET due_at = ?, last_error_fingerprint = ? WHERE task_id = ?",
                    (due, fingerprint, row["task_id"]),
                )
                connection.execute(
                    "UPDATE attempts SET state = 'abandoned', ended_at = ?, failure_id = ? "
                    "WHERE task_id = ? AND ended_at IS NULL",
                    (now, failure_id, row["task_id"]),
                )
            return len(rows)

    @staticmethod
    def _require_claim(connection: Any, claim: TaskClaim) -> None:
        row = connection.execute(
            """
            SELECT 1 FROM leases
            WHERE resource_key = ? AND task_id = ? AND holder = ? AND fence = ?
              AND released_at IS NULL AND julianday(expires_at) > julianday('now')
            """,
            (claim.resource_key, claim.task_id, claim.worker_id, claim.fence),
        ).fetchone()
        if row is None:
            raise LeaseError(
                f"task claim is stale: {claim.task_id} fence {claim.fence}"
            )
        attempt = connection.execute(
            "SELECT 1 FROM attempts WHERE attempt_id = ? AND task_id = ? AND worker_id = ? "
            "AND ended_at IS NULL",
            (claim.attempt_id, claim.task_id, claim.worker_id),
        ).fetchone()
        if attempt is None:
            raise LeaseError(f"attempt is not active: {claim.attempt_id}")

    @staticmethod
    def _record_negative(
        connection: Any,
        task: Mapping[str, Any],
        *,
        fingerprint: str,
        failure_class: str,
        severity: str,
        repair_route: str,
        now: str,
    ) -> str:
        prior = connection.execute(
            "SELECT failure_id FROM negative_results WHERE project_id = ? AND task_id = ? AND fingerprint = ?",
            (task["project_id"], task["task_id"], fingerprint),
        ).fetchone()
        if prior is not None:
            connection.execute(
                "UPDATE negative_results SET last_seen = ?, recurrence_count = recurrence_count + 1 "
                "WHERE failure_id = ?",
                (now, prior["failure_id"]),
            )
            return prior["failure_id"]
        failure_id = str(uuid.uuid4())
        connection.execute(
            """
            INSERT INTO negative_results(
                failure_id, project_id, run_id, task_id, fingerprint,
                failure_class, severity, evidence_refs_json, repair_route,
                first_seen, last_seen, recurrence_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, '[]', ?, ?, ?, 1)
            """,
            (
                failure_id,
                task["project_id"],
                task["run_id"],
                task["task_id"],
                fingerprint,
                failure_class,
                severity,
                repair_route,
                now,
                now,
            ),
        )
        return failure_id
