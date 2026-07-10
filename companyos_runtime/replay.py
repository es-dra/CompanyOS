"""Deterministic replay and verification for core Goal/Run/Task projections."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .errors import IntegrityError
from .identity import IdentityManager, Role, VerifiedPrincipal
from .state_machine import apply_loop_event, require_transition
from .store import SQLiteStore
from .types import (
    GoalSpec,
    GoalState,
    LoopEvent,
    LoopState,
    TaskSpec,
    TaskState,
    canonical_json,
)


_SECONDARY_TASK_TABLES = (
    "attempts",
    "workflow_steps",
    "leases",
    "approvals",
    "capability_grants",
    "outbox",
    "artifacts",
    "evidence_claims",
    "context_assemblies",
    "negative_results",
    "integration_items",
)
_EXECUTION_TASK_STATES = frozenset(
    {
        TaskState.LEASED.value,
        TaskState.RUNNING.value,
        TaskState.SUSPENDED.value,
        TaskState.EVIDENCE_PENDING.value,
        TaskState.EVALUATOR_PENDING.value,
        TaskState.INTEGRATION_PENDING.value,
        TaskState.RETRY_PENDING.value,
        TaskState.FAILED.value,
        TaskState.DELIVERED.value,
    }
)
_DUE_MUST_BE_NULL_STATES = frozenset(
    {
        TaskState.LEASED.value,
        TaskState.RUNNING.value,
        TaskState.SUSPENDED.value,
        TaskState.EVIDENCE_PENDING.value,
        TaskState.EVALUATOR_PENDING.value,
        TaskState.INTEGRATION_PENDING.value,
        TaskState.DELIVERED.value,
        TaskState.FAILED.value,
    }
)
_FAILURE_ATTEMPT_STATES = frozenset({"failed", "abandoned"})


@dataclass(frozen=True)
class ReplayResult:
    goals: dict[str, dict[str, Any]]
    runs: dict[str, dict[str, Any]]
    tasks: dict[str, dict[str, Any]]


class ProjectionReplayer:
    """Rebuilds the core control projections from canonical events.

    Other ledgers (leases, approvals, evidence, observations, outbox, evals) are
    durable first-class tables with event audit, but are not claimed as
    rebuildable by this v1 replayer.  In particular, ``attempts`` and
    ``negative_results`` are mutable, non-hash-chained secondary ledgers.  The
    operational checks below can detect internal disagreement with ``tasks``;
    they neither authenticate collusive secondary-ledger tampering nor turn
    repair into a full historical event rebuild.
    """

    def __init__(self, store: SQLiteStore, *, identity: IdentityManager | None = None):
        self.store = store
        self.identity = identity or IdentityManager(store)

    def replay(self) -> ReplayResult:
        with self.store.transaction() as connection:
            return self._replay_in_transaction(connection)

    def _replay_in_transaction(self, connection: Any) -> ReplayResult:
        """Replay the event chain from one stable transaction snapshot."""

        self.store.verify_event_chain(connection)
        rows = [
            dict(row) for row in connection.execute("SELECT * FROM events ORDER BY seq")
        ]
        goals: dict[str, dict[str, Any]] = {}
        runs: dict[str, dict[str, Any]] = {}
        tasks: dict[str, dict[str, Any]] = {}
        versions: dict[tuple[str, str], int] = {}
        for row in rows:
            aggregate_type = row["aggregate_type"]
            if aggregate_type not in {"goal", "run", "task"}:
                continue
            key = (aggregate_type, row["aggregate_id"])
            expected = versions.get(key, 0) + 1
            if int(row["aggregate_version"]) != expected:
                raise IntegrityError(
                    f"projection event version gap: {key} expected {expected}"
                )
            versions[key] = expected
            payload = json.loads(row["payload_json"])
            if aggregate_type == "goal":
                self._apply_goal(goals, row, payload)
            elif aggregate_type == "run":
                self._apply_run(runs, goals, row, payload)
            else:
                self._apply_task(tasks, goals, runs, row, payload)
        return ReplayResult(goals=goals, runs=runs, tasks=tasks)

    @staticmethod
    def _apply_goal(
        goals: dict[str, dict[str, Any]], row: dict[str, Any], payload: dict[str, Any]
    ) -> None:
        goal_id = row["aggregate_id"]
        if row["event_type"] != "goal_created" or goal_id in goals:
            raise IntegrityError(
                f"unsupported or duplicate goal event: {row['event_type']}:{goal_id}"
            )
        spec = GoalSpec.from_dict(payload)
        if spec.goal_id != goal_id:
            raise IntegrityError("goal event aggregate and payload identifiers differ")
        goals[goal_id] = {
            "goal_id": goal_id,
            "project_id": row["project_id"],
            "state": GoalState.COMPILED.value,
            "spec_json": canonical_json(spec.to_dict()),
            "aggregate_version": int(row["aggregate_version"]),
            "created_at": row["recorded_at"],
            "updated_at": row["recorded_at"],
        }

    @staticmethod
    def _apply_run(
        runs: dict[str, dict[str, Any]],
        goals: dict[str, dict[str, Any]],
        row: dict[str, Any],
        payload: dict[str, Any],
    ) -> None:
        run_id = row["aggregate_id"]
        if run_id not in runs:
            if row["event_type"] != LoopEvent.OWNER_INTENT_RECEIVED.value:
                raise IntegrityError(f"run does not start with owner intent: {run_id}")
            goal_id = payload.get("goal_id")
            if (
                goal_id not in goals
                or goals[goal_id]["project_id"] != row["project_id"]
            ):
                raise IntegrityError(
                    f"run references a missing/cross-project goal: {run_id}"
                )
            runs[run_id] = {
                "run_id": run_id,
                "goal_id": goal_id,
                "project_id": row["project_id"],
                "loop_state": LoopState.INTAKE.value,
                "policy_version": payload["policy_version"],
                "aggregate_version": 1,
                "created_at": row["recorded_at"],
                "updated_at": row["recorded_at"],
            }
            return
        try:
            event = LoopEvent(row["event_type"])
            current = LoopState(runs[run_id]["loop_state"])
            target = apply_loop_event(current, event, payload.get("guards", {}))
        except Exception as exc:
            raise IntegrityError(
                f"run replay failed at {run_id}:{row['event_type']}"
            ) from exc
        runs[run_id]["loop_state"] = target.value
        runs[run_id]["aggregate_version"] = int(row["aggregate_version"])
        runs[run_id]["updated_at"] = row["recorded_at"]

    @staticmethod
    def _apply_task(
        tasks: dict[str, dict[str, Any]],
        goals: dict[str, dict[str, Any]],
        runs: dict[str, dict[str, Any]],
        row: dict[str, Any],
        payload: dict[str, Any],
    ) -> None:
        task_id = row["aggregate_id"]
        if task_id not in tasks:
            if row["event_type"] != "task_added":
                raise IntegrityError(f"task does not start with task_added: {task_id}")
            run_id = payload.pop("run_id", None)
            spec = TaskSpec.from_dict(payload)
            if spec.task_id != task_id or spec.goal_id not in goals:
                raise IntegrityError(
                    "task event references a missing or mismatched goal"
                )
            if run_id is not None and (
                run_id not in runs or runs[run_id]["goal_id"] != spec.goal_id
            ):
                raise IntegrityError(
                    "task event references a missing or mismatched run"
                )
            tasks[task_id] = {
                "task_id": task_id,
                "goal_id": spec.goal_id,
                "run_id": run_id,
                "project_id": row["project_id"],
                "state": TaskState.READY.value,
                "spec_json": canonical_json(spec.to_dict()),
                "aggregate_version": 1,
                "created_at": row["recorded_at"],
                "updated_at": row["recorded_at"],
            }
            return
        if row["event_type"] != "task_state_changed":
            raise IntegrityError(
                f"unsupported task event: {row['event_type']}:{task_id}"
            )
        current = TaskState(tasks[task_id]["state"])
        target = TaskState(payload["target"])
        try:
            require_transition(current, target)
        except Exception as exc:
            raise IntegrityError(f"task replay transition failed: {task_id}") from exc
        tasks[task_id]["state"] = target.value
        tasks[task_id]["aggregate_version"] = int(row["aggregate_version"])
        tasks[task_id]["updated_at"] = row["recorded_at"]

    def verify(self) -> ReplayResult:
        with self.store.transaction() as connection:
            replayed = self._replay_in_transaction(connection)
            self._verify_projections_in_transaction(connection, replayed)
            return replayed

    def _verify_projections_in_transaction(
        self, connection: Any, replayed: ReplayResult
    ) -> None:
        self._verify_table(
            connection,
            "goals",
            "goal_id",
            replayed.goals,
            ("project_id", "state", "spec_json", "aggregate_version"),
        )
        self._verify_table(
            connection,
            "runs",
            "run_id",
            replayed.runs,
            (
                "goal_id",
                "project_id",
                "loop_state",
                "policy_version",
                "aggregate_version",
            ),
        )
        self._verify_table(
            connection,
            "tasks",
            "task_id",
            replayed.tasks,
            (
                "goal_id",
                "run_id",
                "project_id",
                "state",
                "spec_json",
                "aggregate_version",
            ),
        )
        self._verify_task_operational_projections(connection, replayed)

    def _verify_task_operational_projections(
        self, connection: Any, replayed: ReplayResult
    ) -> None:
        """Cross-check task operational fields against secondary ledgers.

        Event replay intentionally cannot derive retry timestamps or failure
        fingerprints.  This method therefore proves only consistency within a
        single transaction snapshot and fails closed whenever that consistency
        is not demonstrable.
        """

        actual_tasks = {
            row["task_id"]: dict(row)
            for row in connection.execute(
                "SELECT task_id, attempt_count, due_at, last_error_fingerprint "
                "FROM tasks"
            )
        }
        attempts_by_task: dict[str, list[dict[str, Any]]] = {}
        for row in connection.execute(
            "SELECT * FROM attempts ORDER BY task_id, attempt_number"
        ):
            attempt = dict(row)
            task_id = str(attempt["task_id"])
            if task_id not in replayed.tasks:
                raise IntegrityError(
                    "attempt secondary ledger references a task without events: "
                    f"{task_id}"
                )
            attempts_by_task.setdefault(task_id, []).append(attempt)

        negatives: dict[str, dict[str, Any]] = {}
        negatives_by_task: dict[str, list[dict[str, Any]]] = {}
        for row in connection.execute("SELECT * FROM negative_results"):
            negative = dict(row)
            failure_id = str(negative["failure_id"])
            task_id = str(negative["task_id"])
            if task_id not in replayed.tasks:
                raise IntegrityError(
                    "negative-result secondary ledger references a task without "
                    f"events: {task_id}"
                )
            negatives[failure_id] = negative
            negatives_by_task.setdefault(task_id, []).append(negative)

        for task_id, projection in replayed.tasks.items():
            actual = actual_tasks.get(task_id)
            if actual is None:
                raise IntegrityError(
                    f"tasks operational projection is missing: {task_id}"
                )
            attempts = attempts_by_task.get(task_id, [])
            attempt_numbers = [int(row["attempt_number"]) for row in attempts]
            expected_numbers = list(range(1, len(attempts) + 1))
            if attempt_numbers != expected_numbers:
                raise IntegrityError(
                    "attempt secondary ledger is not gapless for "
                    f"{task_id}: {attempt_numbers!r}"
                )
            expected_count = attempt_numbers[-1] if attempt_numbers else 0
            if int(actual["attempt_count"]) != expected_count:
                raise IntegrityError(
                    f"tasks operational projection mismatch: {task_id}.attempt_count: "
                    f"{actual['attempt_count']!r} != {expected_count!r}"
                )

            for negative in negatives_by_task.get(task_id, []):
                if (
                    negative["project_id"] != projection["project_id"]
                    or negative["run_id"] != projection["run_id"]
                ):
                    raise IntegrityError(
                        "negative-result secondary ledger crosses task ownership: "
                        f"{negative['failure_id']}"
                    )

            failure_attempts: list[tuple[dict[str, Any], dict[str, Any]]] = []
            for attempt in attempts:
                if attempt["run_id"] != projection["run_id"]:
                    raise IntegrityError(
                        "attempt secondary ledger crosses task run: "
                        f"{attempt['attempt_id']}"
                    )
                failure_id = attempt["failure_id"]
                if failure_id is None:
                    if attempt["state"] in _FAILURE_ATTEMPT_STATES:
                        raise IntegrityError(
                            "failed attempt lacks a negative-result reference: "
                            f"{attempt['attempt_id']}"
                        )
                    continue
                if attempt["state"] not in _FAILURE_ATTEMPT_STATES:
                    raise IntegrityError(
                        "non-failure attempt carries a negative-result reference: "
                        f"{attempt['attempt_id']}"
                    )
                joined_negative = negatives.get(str(failure_id))
                if joined_negative is None:
                    raise IntegrityError(
                        "attempt references a missing negative result: "
                        f"{attempt['attempt_id']}:{failure_id}"
                    )
                if (
                    joined_negative["task_id"] != task_id
                    or joined_negative["project_id"] != projection["project_id"]
                    or joined_negative["run_id"] != projection["run_id"]
                ):
                    raise IntegrityError(
                        "attempt and negative result cross task ownership: "
                        f"{attempt['attempt_id']}:{failure_id}"
                    )
                if attempt["ended_at"] is None:
                    raise IntegrityError(
                        f"failure attempt has no end timestamp: {attempt['attempt_id']}"
                    )
                failure_attempts.append((attempt, joined_negative))

            latest_failure = failure_attempts[-1] if failure_attempts else None
            expected_fingerprint = (
                latest_failure[1]["fingerprint"] if latest_failure is not None else None
            )
            if actual["last_error_fingerprint"] != expected_fingerprint:
                raise IntegrityError(
                    "tasks operational projection mismatch: "
                    f"{task_id}.last_error_fingerprint: "
                    f"{actual['last_error_fingerprint']!r} != "
                    f"{expected_fingerprint!r}"
                )

            self._verify_due_at(
                connection,
                task_id=task_id,
                projection=projection,
                attempt_count=expected_count,
                due_at=actual["due_at"],
                latest_failure=latest_failure,
            )

    @staticmethod
    def _verify_due_at(
        connection: Any,
        *,
        task_id: str,
        projection: dict[str, Any],
        attempt_count: int,
        due_at: Any,
        latest_failure: tuple[dict[str, Any], dict[str, Any]] | None,
    ) -> None:
        state = str(projection["state"])
        spec = TaskSpec.from_dict(json.loads(projection["spec_json"]))
        latest_failure_number = (
            int(latest_failure[0]["attempt_number"])
            if latest_failure is not None
            else None
        )
        if state == TaskState.RETRY_PENDING.value:
            if due_at is None:
                raise IntegrityError(
                    f"tasks operational projection mismatch: {task_id}.due_at is "
                    "required while retry_pending"
                )
            if (
                latest_failure_number != attempt_count
                or attempt_count == 0
                or attempt_count >= spec.max_attempts
            ):
                raise IntegrityError(
                    "retry_pending task is not supported by a retryable latest "
                    f"failure: {task_id}"
                )
        if state == TaskState.FAILED.value and (
            latest_failure_number != attempt_count
            or attempt_count == 0
            or attempt_count < spec.max_attempts
        ):
            raise IntegrityError(
                "failed task is not supported by an exhausted latest failure: "
                f"{task_id}"
            )
        if due_at is None:
            return
        if state in _DUE_MUST_BE_NULL_STATES:
            raise IntegrityError(
                f"tasks operational projection mismatch: {task_id}.due_at must be null "
                f"in state {state}"
            )
        if latest_failure is None or latest_failure_number != attempt_count:
            raise IntegrityError(
                f"tasks operational projection mismatch: {task_id}.due_at has no "
                "latest failure"
            )
        ended_at = latest_failure[0]["ended_at"]
        parsed = connection.execute(
            "SELECT julianday(?), julianday(?)", (due_at, ended_at)
        ).fetchone()
        if (
            parsed[0] is None
            or parsed[1] is None
            or float(parsed[0]) <= float(parsed[1])
        ):
            raise IntegrityError(
                f"tasks operational projection mismatch: {task_id}.due_at is not "
                "after its latest failure"
            )

    def _verify_table(
        self,
        connection: Any,
        table: str,
        key: str,
        expected: dict[str, dict[str, Any]],
        fields: tuple[str, ...],
    ) -> None:
        actual = {
            row[key]: dict(row) for row in connection.execute(f"SELECT * FROM {table}")
        }
        if set(actual) != set(expected):
            raise IntegrityError(
                f"{table} projection identity mismatch: expected={sorted(expected)} actual={sorted(actual)}"
            )
        for object_id, projection in expected.items():
            for field in fields:
                left = actual[object_id][field]
                right = projection[field]
                if field == "spec_json":
                    left = canonical_json(json.loads(left))
                if left != right:
                    raise IntegrityError(
                        f"{table} projection mismatch: {object_id}.{field}: {left!r} != {right!r}"
                    )

    def repair(self, *, actor: VerifiedPrincipal) -> ReplayResult:
        with self.store.transaction(immediate=True) as connection:
            self.identity.require_role_in_transaction(connection, actor, Role.SYSTEM)
            replayed = self._replay_in_transaction(connection)
            task_ids: set[str] = set()
            for table, key, objects in (
                ("goals", "goal_id", replayed.goals),
                ("runs", "run_id", replayed.runs),
                ("tasks", "task_id", replayed.tasks),
            ):
                actual_ids = {
                    row[key] for row in connection.execute(f"SELECT {key} FROM {table}")
                }
                extras = actual_ids - set(objects)
                if extras:
                    raise IntegrityError(
                        "refusing to delete projection rows without events: "
                        f"{table}:{sorted(extras)}"
                    )
                if table == "tasks":
                    task_ids = actual_ids
            for task_id in set(replayed.tasks) - task_ids:
                self._require_safe_missing_task_rebuild(connection, task_id)
            for goal in replayed.goals.values():
                connection.execute(
                    """
                    INSERT INTO goals(goal_id, project_id, state, spec_json, aggregate_version, created_at, updated_at)
                    VALUES (:goal_id, :project_id, :state, :spec_json, :aggregate_version, :created_at, :updated_at)
                    ON CONFLICT(goal_id) DO UPDATE SET project_id=excluded.project_id,
                      state=excluded.state, spec_json=excluded.spec_json,
                      aggregate_version=excluded.aggregate_version, updated_at=excluded.updated_at
                    """,
                    goal,
                )
            for run in replayed.runs.values():
                connection.execute(
                    """
                    INSERT INTO runs(run_id, goal_id, project_id, loop_state, policy_version,
                      aggregate_version, created_at, updated_at)
                    VALUES (:run_id, :goal_id, :project_id, :loop_state, :policy_version,
                      :aggregate_version, :created_at, :updated_at)
                    ON CONFLICT(run_id) DO UPDATE SET goal_id=excluded.goal_id,
                      project_id=excluded.project_id, loop_state=excluded.loop_state,
                      policy_version=excluded.policy_version,
                      aggregate_version=excluded.aggregate_version, updated_at=excluded.updated_at
                    """,
                    run,
                )
            for task in replayed.tasks.values():
                connection.execute(
                    """
                    INSERT INTO tasks(task_id, goal_id, run_id, project_id, state,
                      spec_json, aggregate_version, attempt_count, created_at, updated_at)
                    VALUES (:task_id, :goal_id, :run_id, :project_id, :state,
                      :spec_json, :aggregate_version, 0, :created_at, :updated_at)
                    ON CONFLICT(task_id) DO UPDATE SET goal_id=excluded.goal_id,
                      run_id=excluded.run_id, project_id=excluded.project_id,
                      state=excluded.state, spec_json=excluded.spec_json,
                      aggregate_version=excluded.aggregate_version, updated_at=excluded.updated_at
                    """,
                    task,
                )
            # A failed post-write comparison rolls back the entire repair.
            # BEGIN IMMEDIATE also prevents a core writer from advancing the
            # event head between replay and this comparison.
            self._verify_projections_in_transaction(connection, replayed)
        return replayed

    @staticmethod
    def _require_safe_missing_task_rebuild(connection: Any, task_id: str) -> None:
        occupied_tables = [
            table
            for table in _SECONDARY_TASK_TABLES
            if connection.execute(
                f"SELECT 1 FROM {table} WHERE task_id = ? LIMIT 1", (task_id,)
            ).fetchone()
            is not None
        ]
        if occupied_tables:
            raise IntegrityError(
                "refusing to reconstruct missing task with secondary operational "
                f"rows: {task_id}:{occupied_tables}"
            )
        for row in connection.execute(
            "SELECT event_type, payload_json FROM events "
            "WHERE aggregate_type = 'task' AND aggregate_id = ? ORDER BY seq",
            (task_id,),
        ):
            if row["event_type"] != "task_state_changed":
                continue
            target = json.loads(row["payload_json"]).get("target")
            if target in _EXECUTION_TASK_STATES:
                raise IntegrityError(
                    "refusing to guess missing scheduler projection after execution "
                    f"history: {task_id}:{target}"
                )
