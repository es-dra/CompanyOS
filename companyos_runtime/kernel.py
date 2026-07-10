"""Application boundary for durable CompanyOS goal, run, and task commands."""

from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any, Mapping

from .errors import ContractError, NotFoundError, TransitionError
from .gates import GuardResolver
from .identity import IdentityManager, Role, VerifiedPrincipal
from .scope import validate_goal_scope, validate_task_within_goal
from .state_machine import apply_loop_event, require_transition
from .store import SQLiteStore
from .types import (
    GoalSpec,
    GoalState,
    LoopEvent,
    LoopState,
    RuntimeSurfaceSpec,
    TaskSpec,
    TaskState,
    canonical_json,
    content_hash,
    utc_now,
)


_TASK_CONTROL_TARGETS = {
    "block": TaskState.BLOCKED,
    "cancel": TaskState.CANCELED,
    "delete": TaskState.DELETED,
    "retire": TaskState.RETIRED,
    "suspend": TaskState.SUSPENDED,
}


class RuntimeKernel:
    """Coordinates strict contracts, events, and rebuildable projections."""

    def __init__(
        self,
        store: SQLiteStore,
        *,
        policy_version: str = "companyos-policy-v1",
        identity: IdentityManager | None = None,
    ):
        self.store = store
        self.__command_authority = store._bind_core_command_authority(
            self, "runtime_kernel"
        )
        self.policy_version = policy_version
        self.guards = GuardResolver()
        self.identity = identity or IdentityManager(store)

    def _actor_id(self, actor: VerifiedPrincipal, allowed_roles: set[Role]) -> str:
        principal = self.identity.verify(actor)
        if not principal.roles.intersection(allowed_roles):
            expected = ", ".join(sorted(role.value for role in allowed_roles))
            raise TransitionError(
                f"authenticated actor requires one of roles: {expected}"
            )
        return principal.principal_id

    def _loop_actor_id(self, actor: VerifiedPrincipal, event: LoopEvent) -> str:
        roles = {
            LoopEvent.GOAL_COMPILED: {Role.SYSTEM},
            LoopEvent.RUN_READY: {Role.SYSTEM},
            LoopEvent.TASK_STARTED: {Role.WORKER, Role.SYSTEM},
            LoopEvent.HUMAN_APPROVAL_REQUESTED: {Role.WORKER, Role.SYSTEM},
            LoopEvent.HUMAN_APPROVAL_RECEIVED: {Role.OWNER, Role.SYSTEM},
            LoopEvent.EVIDENCE_SUBMITTED: {Role.WORKER, Role.SYSTEM},
            LoopEvent.EVALUATOR_VERDICT_RECEIVED: {Role.EVALUATOR},
            LoopEvent.CI_CHECK_STARTED: {Role.RELEASE, Role.SYSTEM},
            LoopEvent.CI_CHECK_COMPLETED: {Role.RELEASE, Role.SYSTEM},
            LoopEvent.DEPLOY_DIRECTORY_UPDATED: {Role.RELEASE},
            LoopEvent.SERVICE_RESTART_ATTEMPTED: {Role.RELEASE},
            LoopEvent.RUNTIME_FRESHNESS_VERIFIED: {Role.OBSERVER},
            LoopEvent.RUNTIME_DRIFT_DETECTED: {Role.OBSERVER, Role.SYSTEM},
            LoopEvent.DELIVERY_CONFIRMED: {Role.RELEASE},
            LoopEvent.IMPROVEMENT_REQUESTED: {Role.OWNER, Role.SYSTEM},
            LoopEvent.RESUME_REQUESTED: {Role.OWNER, Role.SYSTEM},
        }.get(event, {Role.SYSTEM})
        return self._actor_id(actor, roles)

    def initialize(self) -> None:
        self.store.initialize()

    @staticmethod
    def _command_id() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def _command_text(value: Any, field: str) -> str:
        if not isinstance(value, str) or not value:
            raise ContractError(f"{field} must be a non-empty string")
        if value != value.strip():
            raise ContractError(f"{field} must not contain surrounding whitespace")
        return value

    @staticmethod
    def _validate_runtime_surfaces(value: Any, *, owner: str) -> None:
        if type(value) is not tuple:
            raise ContractError(f"{owner}.required_runtime_surfaces must be a tuple")
        surfaces = value
        for surface in surfaces:
            if type(surface) is not RuntimeSurfaceSpec:
                raise ContractError(
                    f"{owner}.required_runtime_surfaces must contain "
                    "RuntimeSurfaceSpec values"
                )
            if type(surface.allowed_probes) is not tuple:
                raise ContractError(
                    "runtime_surface_spec.allowed_probes must be a tuple"
                )

    @classmethod
    def _canonical_goal_spec(cls, spec: GoalSpec) -> GoalSpec:
        if type(spec) is not GoalSpec:
            raise ContractError("create_goal requires an exact GoalSpec value")
        for field_name in (
            "success_evidence_states",
            "read_scope",
            "write_scope",
            "forbidden_scope",
            "allowed_capabilities",
            "required_runtime_surfaces",
            "non_goals",
        ):
            if type(getattr(spec, field_name)) is not tuple:
                raise ContractError(f"goal_spec.{field_name} must be a tuple")
        cls._validate_runtime_surfaces(
            spec.required_runtime_surfaces, owner="goal_spec"
        )
        if type(spec.max_iterations_without_evidence) is not int:
            raise ContractError(
                "max_iterations_without_evidence must be a positive integer"
            )
        try:
            canonical = GoalSpec.from_dict(spec.to_dict())
        except ContractError:
            raise
        except Exception as exc:
            raise ContractError("malformed directly constructed GoalSpec") from exc
        validate_goal_scope(canonical)
        return canonical

    @classmethod
    def _canonical_task_spec(cls, spec: TaskSpec) -> TaskSpec:
        if type(spec) is not TaskSpec:
            raise ContractError("add_task requires an exact TaskSpec value")
        for field_name in (
            "capabilities",
            "read_scope",
            "write_scope",
            "forbidden_scope",
            "required_runtime_surfaces",
            "workflow_steps",
        ):
            if type(getattr(spec, field_name)) is not tuple:
                raise ContractError(f"task_spec.{field_name} must be a tuple")
        cls._validate_runtime_surfaces(
            spec.required_runtime_surfaces, owner="task_spec"
        )
        if type(spec.max_attempts) is not int:
            raise ContractError("max_attempts must be a positive integer")
        try:
            return TaskSpec.from_dict(spec.to_dict())
        except ContractError:
            raise
        except Exception as exc:
            raise ContractError("malformed directly constructed TaskSpec") from exc

    def create_goal(
        self,
        *,
        project_id: str,
        spec: GoalSpec,
        actor: VerifiedPrincipal,
        idempotency_key: str,
    ) -> dict[str, Any]:
        project_id = self._command_text(project_id, "project_id")
        idempotency_key = self._command_text(idempotency_key, "idempotency_key")
        actor_id = self._actor_id(actor, {Role.OWNER})
        spec = self._canonical_goal_spec(spec)
        payload = spec.to_dict()
        digest = content_hash(payload)
        with self.store.transaction(immediate=True) as connection:
            prior = self.store.get_idempotent_result(
                connection,
                project_id=project_id,
                scope="goal.create",
                key=idempotency_key,
                payload_digest=digest,
            )
            if prior is not None:
                return prior
            if connection.execute(
                "SELECT 1 FROM goals WHERE goal_id = ?", (spec.goal_id,)
            ).fetchone():
                raise sqlite3.IntegrityError(f"goal already exists: {spec.goal_id}")
            event = self.store.append_event(
                connection,
                aggregate_type="goal",
                aggregate_id=spec.goal_id,
                expected_version=0,
                project_id=project_id,
                event_type="goal_created",
                actor=actor_id,
                auth_session=actor,
                command_id=self._command_id(),
                correlation_id=spec.goal_id,
                policy_version=self.policy_version,
                payload=payload,
                command_authority=self.__command_authority,
                idempotency_key=idempotency_key,
            )
            now = utc_now()
            connection.execute(
                "INSERT INTO goals(goal_id, project_id, state, spec_json, aggregate_version, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    spec.goal_id,
                    project_id,
                    GoalState.COMPILED.value,
                    canonical_json(payload),
                    1,
                    now,
                    now,
                ),
            )
            result = {
                "goal_id": spec.goal_id,
                "state": GoalState.COMPILED.value,
                "event_id": event["event_id"],
            }
            self.store.save_idempotent_result(
                connection,
                project_id=project_id,
                scope="goal.create",
                key=idempotency_key,
                payload_digest=digest,
                result=result,
                event_id=event["event_id"],
            )
            return result

    def create_run(
        self,
        *,
        project_id: str,
        goal_id: str,
        run_id: str,
        actor: VerifiedPrincipal,
        idempotency_key: str,
    ) -> dict[str, Any]:
        project_id = self._command_text(project_id, "project_id")
        goal_id = self._command_text(goal_id, "goal_id")
        run_id = self._command_text(run_id, "run_id")
        idempotency_key = self._command_text(idempotency_key, "idempotency_key")
        actor_id = self._actor_id(actor, {Role.OWNER, Role.SYSTEM})
        payload = {
            "goal_id": goal_id,
            "run_id": run_id,
            "policy_version": self.policy_version,
        }
        digest = content_hash(payload)
        with self.store.transaction(immediate=True) as connection:
            prior = self.store.get_idempotent_result(
                connection,
                project_id=project_id,
                scope="run.create",
                key=idempotency_key,
                payload_digest=digest,
            )
            if prior is not None:
                return prior
            goal = connection.execute(
                "SELECT project_id FROM goals WHERE goal_id = ?", (goal_id,)
            ).fetchone()
            if goal is None or goal["project_id"] != project_id:
                raise NotFoundError(f"goal not found in project: {goal_id}")
            event = self.store.append_event(
                connection,
                aggregate_type="run",
                aggregate_id=run_id,
                expected_version=0,
                project_id=project_id,
                run_id=run_id,
                event_type=LoopEvent.OWNER_INTENT_RECEIVED.value,
                actor=actor_id,
                auth_session=actor,
                command_id=self._command_id(),
                correlation_id=run_id,
                policy_version=self.policy_version,
                payload=payload,
                command_authority=self.__command_authority,
                idempotency_key=idempotency_key,
            )
            now = utc_now()
            connection.execute(
                "INSERT INTO runs(run_id, goal_id, project_id, loop_state, policy_version, "
                "aggregate_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    goal_id,
                    project_id,
                    LoopState.INTAKE.value,
                    self.policy_version,
                    1,
                    now,
                    now,
                ),
            )
            result = {
                "run_id": run_id,
                "goal_id": goal_id,
                "loop_state": LoopState.INTAKE.value,
                "event_id": event["event_id"],
            }
            self.store.save_idempotent_result(
                connection,
                project_id=project_id,
                scope="run.create",
                key=idempotency_key,
                payload_digest=digest,
                result=result,
                event_id=event["event_id"],
            )
            return result

    def add_task(
        self,
        *,
        project_id: str,
        spec: TaskSpec,
        actor: VerifiedPrincipal,
        idempotency_key: str,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        project_id = self._command_text(project_id, "project_id")
        idempotency_key = self._command_text(idempotency_key, "idempotency_key")
        if run_id is not None:
            run_id = self._command_text(run_id, "run_id")
        actor_id = self._actor_id(actor, {Role.OWNER, Role.SYSTEM})
        spec = self._canonical_task_spec(spec)
        payload = spec.to_dict() | {"run_id": run_id}
        digest = content_hash(payload)
        with self.store.transaction(immediate=True) as connection:
            prior = self.store.get_idempotent_result(
                connection,
                project_id=project_id,
                scope="task.add",
                key=idempotency_key,
                payload_digest=digest,
            )
            if prior is not None:
                return prior
            goal = connection.execute(
                "SELECT project_id, spec_json FROM goals WHERE goal_id = ?",
                (spec.goal_id,),
            ).fetchone()
            if goal is None or goal["project_id"] != project_id:
                raise NotFoundError(f"goal not found in project: {spec.goal_id}")
            validate_task_within_goal(
                GoalSpec.from_dict(json.loads(goal["spec_json"])), spec
            )
            if run_id is not None:
                run = connection.execute(
                    "SELECT project_id, goal_id, loop_state FROM runs WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                if (
                    run is None
                    or run["project_id"] != project_id
                    or run["goal_id"] != spec.goal_id
                ):
                    raise NotFoundError(f"run not found for goal/project: {run_id}")
                if run["loop_state"] in {
                    LoopState.DELIVERED.value,
                    LoopState.IMPROVEMENT_PENDING.value,
                }:
                    raise TransitionError(
                        f"delivered run is sealed against new tasks: {run_id}"
                    )
            event = self.store.append_event(
                connection,
                aggregate_type="task",
                aggregate_id=spec.task_id,
                expected_version=0,
                project_id=project_id,
                run_id=run_id,
                task_id=spec.task_id,
                event_type="task_added",
                actor=actor_id,
                auth_session=actor,
                command_id=self._command_id(),
                correlation_id=run_id or spec.goal_id,
                policy_version=self.policy_version,
                payload=payload,
                command_authority=self.__command_authority,
                idempotency_key=idempotency_key,
            )
            now = utc_now()
            connection.execute(
                "INSERT INTO tasks(task_id, goal_id, run_id, project_id, state, spec_json, "
                "aggregate_version, due_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    spec.task_id,
                    spec.goal_id,
                    run_id,
                    project_id,
                    TaskState.READY.value,
                    canonical_json(spec.to_dict()),
                    1,
                    None,
                    now,
                    now,
                ),
            )
            result = {
                "task_id": spec.task_id,
                "state": TaskState.READY.value,
                "event_id": event["event_id"],
            }
            self.store.save_idempotent_result(
                connection,
                project_id=project_id,
                scope="task.add",
                key=idempotency_key,
                payload_digest=digest,
                result=result,
                event_id=event["event_id"],
            )
            return result

    def advance_loop(
        self,
        *,
        run_id: str,
        event: LoopEvent,
        actor: VerifiedPrincipal,
        idempotency_key: str,
        guard_results: Mapping[str, bool] | None = None,
        payload: Mapping[str, Any] | None = None,
        causation_id: str | None = None,
    ) -> dict[str, Any]:
        run_id = self._command_text(run_id, "run_id")
        idempotency_key = self._command_text(idempotency_key, "idempotency_key")
        if causation_id is not None:
            causation_id = self._command_text(causation_id, "causation_id")
        if type(event) is not LoopEvent:
            raise ContractError("event must be an exact LoopEvent value")
        actor_id = self._loop_actor_id(actor, event)
        event_payload = dict(payload or {})
        with self.store.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"run not found: {run_id}")
            project_id = row["project_id"]
            if event is LoopEvent.TASK_STARTED:
                goal_row = connection.execute(
                    "SELECT spec_json FROM goals WHERE goal_id = ?",
                    (row["goal_id"],),
                ).fetchone()
                goal_spec = GoalSpec.from_dict(json.loads(goal_row["spec_json"]))
                last_evidence = connection.execute(
                    "SELECT MAX(created_at) AS at FROM evidence_claims WHERE run_id = ?",
                    (run_id,),
                ).fetchone()["at"]
                attempts_without_evidence = connection.execute(
                    "SELECT COUNT(*) FROM events WHERE aggregate_type = 'run' "
                    "AND aggregate_id = ? AND event_type = ? "
                    "AND (? IS NULL OR julianday(occurred_at) > julianday(?))",
                    (
                        run_id,
                        LoopEvent.TASK_STARTED.value,
                        last_evidence,
                        last_evidence,
                    ),
                ).fetchone()[0]
                if (
                    int(attempts_without_evidence)
                    >= goal_spec.max_iterations_without_evidence
                ):
                    raise TransitionError(
                        "max_iterations_without_evidence circuit breaker is open"
                    )
            request_digest = content_hash(
                {"event": event.value, "payload": event_payload}
            )
            prior = self.store.get_idempotent_result(
                connection,
                project_id=project_id,
                scope=f"run.event.{run_id}",
                key=idempotency_key,
                payload_digest=request_digest,
            )
            if prior is not None:
                return prior
            authoritative_guards = self.guards.resolve(
                connection,
                run=row,
                event=event,
                payload=event_payload,
                command_actor=actor_id,
            )
            supplied_guards = dict(guard_results or {})
            contradictions = {
                key: (value, authoritative_guards.get(key))
                for key, value in supplied_guards.items()
                if key in authoritative_guards
                and value is not authoritative_guards[key]
            }
            if contradictions:
                raise TransitionError(
                    f"caller guard results contradict persisted runtime facts: {contradictions}"
                )
            command_payload = {
                "event": event.value,
                "guards": authoritative_guards,
                "payload": event_payload,
            }
            current = LoopState(row["loop_state"])
            target = apply_loop_event(current, event, authoritative_guards)
            version = int(row["aggregate_version"])
            appended = self.store.append_event(
                connection,
                aggregate_type="run",
                aggregate_id=run_id,
                expected_version=version,
                project_id=project_id,
                run_id=run_id,
                event_type=event.value,
                actor=actor_id,
                auth_session=actor,
                command_id=self._command_id(),
                correlation_id=run_id,
                policy_version=row["policy_version"],
                payload=command_payload,
                command_authority=self.__command_authority,
                idempotency_key=idempotency_key,
                causation_id=causation_id,
            )
            connection.execute(
                "UPDATE runs SET loop_state = ?, aggregate_version = ?, updated_at = ? WHERE run_id = ?",
                (target.value, version + 1, utc_now(), run_id),
            )
            result = {
                "run_id": run_id,
                "previous_state": current.value,
                "loop_state": target.value,
                "event_id": appended["event_id"],
            }
            self.store.save_idempotent_result(
                connection,
                project_id=project_id,
                scope=f"run.event.{run_id}",
                key=idempotency_key,
                payload_digest=request_digest,
                result=result,
                event_id=appended["event_id"],
            )
            return result

    @staticmethod
    def _task_evidence_status(
        connection: Any, row: Mapping[str, Any]
    ) -> tuple[bool, bool]:
        from .types import EvaluatorVerdict

        spec = TaskSpec.from_dict(json.loads(row["spec_json"]))
        claims = connection.execute(
            "SELECT evaluator_verdict FROM evidence_claims "
            "WHERE task_id = ? AND evidence_state = ?",
            (row["task_id"], spec.evidence_target.value),
        ).fetchall()
        evidence_ok = any(
            claim["evaluator_verdict"]
            in {
                EvaluatorVerdict.NOT_REQUIRED.value,
                EvaluatorVerdict.PASS.value,
                EvaluatorVerdict.PASS_WITH_RISK.value,
            }
            for claim in claims
        )
        evaluator_ok = not spec.evaluator_required or any(
            claim["evaluator_verdict"]
            in {
                EvaluatorVerdict.PASS.value,
                EvaluatorVerdict.PASS_WITH_RISK.value,
            }
            for claim in claims
        )
        return evidence_ok, evaluator_ok

    def _transition_task_projection(
        self,
        connection: Any,
        row: Mapping[str, Any],
        *,
        target: TaskState,
        actor: str,
        reason: str,
        idempotency_key: str,
        auth_session: VerifiedPrincipal,
    ) -> dict[str, Any]:
        current = TaskState(row["state"])
        require_transition(current, target)
        version = int(row["aggregate_version"])
        appended = self.store.append_event(
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
            command_id=self._command_id(),
            correlation_id=row["run_id"] or row["goal_id"],
            policy_version=self.policy_version,
            payload={"from": current.value, "target": target.value, "reason": reason},
            command_authority=self.__command_authority,
            idempotency_key=idempotency_key,
        )
        connection.execute(
            "UPDATE tasks SET state = ?, aggregate_version = ?, updated_at = ? WHERE task_id = ?",
            (target.value, version + 1, utc_now(), row["task_id"]),
        )
        return {
            "task_id": row["task_id"],
            "previous_state": current.value,
            "state": target.value,
            "event_id": appended["event_id"],
        }

    def accept_task_evidence(
        self,
        *,
        task_id: str,
        actor: VerifiedPrincipal,
        idempotency_key: str,
        evidence_id: str,
    ) -> dict[str, Any]:
        task_id = self._command_text(task_id, "task_id")
        idempotency_key = self._command_text(idempotency_key, "idempotency_key")
        evidence_id = self._command_text(evidence_id, "evidence_id")
        actor_id = self._actor_id(actor, {Role.EVALUATOR, Role.SYSTEM})
        payload = {"evidence_id": evidence_id}
        digest = content_hash(payload)
        with self.store.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"task not found: {task_id}")
            project_id = row["project_id"]
            prior = self.store.get_idempotent_result(
                connection,
                project_id=project_id,
                scope=f"task.evidence.{task_id}",
                key=idempotency_key,
                payload_digest=digest,
            )
            if prior is not None:
                return prior
            claim = connection.execute(
                "SELECT evidence_state, evaluator_verdict FROM evidence_claims "
                "WHERE evidence_id = ? AND task_id = ?",
                (evidence_id, task_id),
            ).fetchone()
            if claim is None:
                raise TransitionError(
                    "evidence claim is missing or belongs to another task"
                )
            from .types import EvaluatorVerdict

            task_spec = TaskSpec.from_dict(json.loads(row["spec_json"]))
            accepted_verdicts = {
                EvaluatorVerdict.PASS.value,
                EvaluatorVerdict.PASS_WITH_RISK.value,
            }
            if not task_spec.evaluator_required:
                accepted_verdicts.add(EvaluatorVerdict.NOT_REQUIRED.value)
            if (
                claim["evidence_state"] != task_spec.evidence_target.value
                or claim["evaluator_verdict"] not in accepted_verdicts
            ):
                raise TransitionError(
                    "supplied evidence claim does not itself pass the task target"
                )
            evidence_ok, evaluator_ok = self._task_evidence_status(connection, row)
            if not evidence_ok:
                raise TransitionError("task evidence target is not satisfied")
            current = TaskState(row["state"])
            if current is TaskState.EVIDENCE_PENDING and not evaluator_ok:
                target = TaskState.EVALUATOR_PENDING
            elif (
                current in {TaskState.EVIDENCE_PENDING, TaskState.EVALUATOR_PENDING}
                and evaluator_ok
            ):
                target = TaskState.INTEGRATION_PENDING
            else:
                raise TransitionError(
                    f"task cannot accept evidence from state: {current.value}"
                )
            result = self._transition_task_projection(
                connection,
                row,
                target=target,
                actor=actor_id,
                reason=f"authoritative evidence accepted: {evidence_id}",
                idempotency_key=idempotency_key,
                auth_session=actor,
            )
            self.store.save_idempotent_result(
                connection,
                project_id=project_id,
                scope=f"task.evidence.{task_id}",
                key=idempotency_key,
                payload_digest=digest,
                result=result,
                event_id=result["event_id"],
            )
            return result

    def confirm_task_delivery(
        self,
        *,
        task_id: str,
        actor: VerifiedPrincipal,
        idempotency_key: str,
    ) -> dict[str, Any]:
        task_id = self._command_text(task_id, "task_id")
        idempotency_key = self._command_text(idempotency_key, "idempotency_key")
        actor_id = self._actor_id(actor, {Role.RELEASE})
        payload = {"command": "confirm_task_delivery"}
        digest = content_hash(payload)
        with self.store.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"task not found: {task_id}")
            project_id = row["project_id"]
            prior = self.store.get_idempotent_result(
                connection,
                project_id=project_id,
                scope=f"task.delivery.{task_id}",
                key=idempotency_key,
                payload_digest=digest,
            )
            if prior is not None:
                return prior
            if TaskState(row["state"]) is not TaskState.INTEGRATION_PENDING:
                raise TransitionError(
                    "task must be integration_pending before delivery"
                )
            evidence_ok, evaluator_ok = self._task_evidence_status(connection, row)
            if not evidence_ok or not evaluator_ok:
                raise TransitionError(
                    "task evidence/evaluator requirements are not satisfied"
                )
            spec = TaskSpec.from_dict(json.loads(row["spec_json"]))
            declared_steps = {step["step_id"] for step in spec.workflow_steps}
            if declared_steps:
                step_rows = connection.execute(
                    "SELECT step_id, status FROM workflow_steps WHERE task_id = ?",
                    (task_id,),
                ).fetchall()
                actual_steps = {step["step_id"]: step["status"] for step in step_rows}
                if set(actual_steps) != declared_steps or any(
                    status != "succeeded" for status in actual_steps.values()
                ):
                    missing = sorted(declared_steps - set(actual_steps))
                    unexpected = sorted(set(actual_steps) - declared_steps)
                    incomplete = sorted(
                        step_id
                        for step_id, status in actual_steps.items()
                        if status != "succeeded"
                    )
                    raise TransitionError(
                        "task workflow steps are not exactly durably succeeded: "
                        f"missing={missing}, unexpected={unexpected}, "
                        f"incomplete={incomplete}"
                    )
            integration_rows = connection.execute(
                "SELECT state FROM integration_items WHERE task_id = ?", (task_id,)
            ).fetchall()
            final_integration = {"delivered", "superseded"}
            if spec.integration_required and (
                not integration_rows
                or any(
                    item["state"] not in final_integration for item in integration_rows
                )
            ):
                raise TransitionError("task integration requirements are not satisfied")
            run = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (row["run_id"],)
            ).fetchone()
            if run is None or not self.guards._freshness_satisfied(connection, run):
                raise TransitionError(
                    "task runtime freshness requirements are not satisfied"
                )
            result = self._transition_task_projection(
                connection,
                row,
                target=TaskState.DELIVERED,
                actor=actor_id,
                reason="persisted evidence, evaluator, integration and freshness satisfied",
                idempotency_key=idempotency_key,
                auth_session=actor,
            )
            self.store.save_idempotent_result(
                connection,
                project_id=project_id,
                scope=f"task.delivery.{task_id}",
                key=idempotency_key,
                payload_digest=digest,
                result=result,
                event_id=result["event_id"],
            )
            return result

    def control_task(
        self,
        *,
        task_id: str,
        action: str,
        reason: str,
        actor: VerifiedPrincipal,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Execute one explicit owner/system task control action.

        This is intentionally narrower than a public transition primitive.
        Every action still passes through ``TASK_TRANSITIONS`` and the opaque
        RuntimeKernel event capability.  Suspending preserves the live worker
        claim; resuming a suspended task requires that exact claim to remain
        current, while resuming a blocked task returns it to the scheduler.
        """

        task_id = self._command_text(task_id, "task_id")
        idempotency_key = self._command_text(idempotency_key, "idempotency_key")
        actor_id = self._actor_id(actor, {Role.OWNER, Role.SYSTEM})
        if not isinstance(action, str) or not action.strip():
            raise ContractError("task control action must be a non-empty string")
        normalized_action = action.strip().lower()
        if normalized_action not in {*_TASK_CONTROL_TARGETS, "resume"}:
            raise ContractError(
                "task control action must be one of: "
                "block, cancel, delete, retire, resume, suspend"
            )
        if not isinstance(reason, str) or not reason.strip():
            raise ContractError("task control reason must be a non-empty string")
        normalized_reason = reason.strip()
        payload = {"action": normalized_action, "reason": normalized_reason}
        digest = content_hash(payload)
        with self.store.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"task not found: {task_id}")
            project_id = row["project_id"]
            scope = f"task.control.{task_id}"
            prior = self.store.get_idempotent_result(
                connection,
                project_id=project_id,
                scope=scope,
                key=idempotency_key,
                payload_digest=digest,
            )
            if prior is not None:
                return prior
            current = TaskState(row["state"])
            if normalized_action == "resume":
                if current is TaskState.BLOCKED:
                    target = TaskState.READY
                elif current is TaskState.SUSPENDED:
                    live_claim = connection.execute(
                        "SELECT 1 FROM leases WHERE resource_key = ? "
                        "AND project_id = ? AND task_id = ? AND released_at IS NULL "
                        "AND julianday(expires_at) > julianday('now')",
                        (f"task://{task_id}", project_id, task_id),
                    ).fetchone()
                    if live_claim is None:
                        raise TransitionError(
                            "suspended task cannot resume without its current worker claim"
                        )
                    target = TaskState.LEASED
                else:
                    raise TransitionError(
                        f"task cannot resume from state: {current.value}"
                    )
            else:
                target = _TASK_CONTROL_TARGETS[normalized_action]
            result = self._transition_task_projection(
                connection,
                row,
                target=target,
                actor=actor_id,
                reason=f"control:{normalized_action}: {normalized_reason}",
                idempotency_key=idempotency_key,
                auth_session=actor,
            )
            if target in {
                TaskState.BLOCKED,
                TaskState.CANCELED,
                TaskState.DELETED,
                TaskState.RETIRED,
            }:
                ended_at = utc_now()
                connection.execute(
                    "UPDATE leases SET released_at = ? WHERE task_id = ? "
                    "AND released_at IS NULL",
                    (ended_at, task_id),
                )
                connection.execute(
                    "UPDATE attempts SET state = ?, ended_at = ? WHERE task_id = ? "
                    "AND ended_at IS NULL",
                    (target.value, ended_at, task_id),
                )
            self.store.save_idempotent_result(
                connection,
                project_id=project_id,
                scope=scope,
                key=idempotency_key,
                payload_digest=digest,
                result=result,
                event_id=result["event_id"],
            )
            return result

    def get_goal(self, goal_id: str) -> dict[str, Any]:
        return self._get_projection(
            "goals",
            "goal_id",
            self._command_text(goal_id, "goal_id"),
            "spec_json",
        )

    def get_run(self, run_id: str) -> dict[str, Any]:
        return self._get_projection(
            "runs", "run_id", self._command_text(run_id, "run_id")
        )

    def get_task(self, task_id: str) -> dict[str, Any]:
        return self._get_projection(
            "tasks",
            "task_id",
            self._command_text(task_id, "task_id"),
            "spec_json",
        )

    def _get_projection(
        self, table: str, id_column: str, object_id: str, json_column: str | None = None
    ) -> dict[str, Any]:
        rows = self.store.query(
            f"SELECT * FROM {table} WHERE {id_column} = ?", (object_id,)
        )
        if not rows:
            raise NotFoundError(f"{table[:-1]} not found: {object_id}")
        result = rows[0]
        if json_column and result.get(json_column):
            result[json_column.removesuffix("_json")] = json.loads(
                result.pop(json_column)
            )
        return result
