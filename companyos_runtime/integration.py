"""Durable Integration Queue with explicit, non-collapsing runtime states."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .errors import EvidenceError, IntegrityError, NotFoundError, TransitionError
from .identity import IdentityManager, Role, VerifiedPrincipal
from .store import SQLiteStore
from .types import (
    TERMINAL_TASK_STATES,
    EvaluatorVerdict,
    IntegrationState,
    LoopState,
    TaskSpec,
    TaskState,
    canonical_json,
    utc_now,
)


_FINAL = {IntegrationState.DELIVERED, IntegrationState.SUPERSEDED}

_TRANSITIONS: Mapping[IntegrationState, frozenset[IntegrationState]] = {
    IntegrationState.REVIEW_PENDING: frozenset(
        {
            IntegrationState.EVALUATOR_PENDING,
            IntegrationState.PUSH_PR_PENDING,
            IntegrationState.DEPLOY_PENDING,
            IntegrationState.DELETE_PENDING,
            IntegrationState.RETIRE_PENDING,
            IntegrationState.DELIVERED,
            IntegrationState.DEFER_WITH_OWNER,
            IntegrationState.SUPERSEDED,
        }
    ),
    IntegrationState.EVALUATOR_PENDING: frozenset(
        {
            IntegrationState.REVIEW_PENDING,
            IntegrationState.PUSH_PR_PENDING,
            IntegrationState.DEFER_WITH_OWNER,
            IntegrationState.SUPERSEDED,
        }
    ),
    IntegrationState.PUSH_PR_PENDING: frozenset(
        {
            IntegrationState.CI_PENDING,
            IntegrationState.DEFER_WITH_OWNER,
            IntegrationState.SUPERSEDED,
        }
    ),
    IntegrationState.CI_PENDING: frozenset(
        {
            IntegrationState.MERGE_PENDING,
            IntegrationState.CI_FAILED,
            IntegrationState.DEFER_WITH_OWNER,
        }
    ),
    IntegrationState.CI_FAILED: frozenset(
        {
            IntegrationState.PUSH_PR_PENDING,
            IntegrationState.DEFER_WITH_OWNER,
            IntegrationState.SUPERSEDED,
        }
    ),
    IntegrationState.MERGE_PENDING: frozenset(
        {
            IntegrationState.DEPLOY_PENDING,
            IntegrationState.DELIVERED,
            IntegrationState.DEFER_WITH_OWNER,
        }
    ),
    IntegrationState.DEPLOY_PENDING: frozenset(
        {
            IntegrationState.DEPLOY_DIR_UPDATED,
            IntegrationState.DEFER_WITH_OWNER,
            IntegrationState.SUPERSEDED,
        }
    ),
    IntegrationState.DEPLOY_DIR_UPDATED: frozenset(
        {
            IntegrationState.SERVICE_RESTART_REQUIRED,
            IntegrationState.RUNTIME_CHECK_PENDING,
            IntegrationState.DEFER_WITH_OWNER,
        }
    ),
    IntegrationState.SERVICE_RESTART_REQUIRED: frozenset(
        {
            IntegrationState.RUNTIME_CHECK_PENDING,
            IntegrationState.DEFER_WITH_OWNER,
        }
    ),
    IntegrationState.RUNTIME_CHECK_PENDING: frozenset(
        {
            IntegrationState.DELIVERED,
            IntegrationState.RUNTIME_STALE,
            IntegrationState.DEFER_WITH_OWNER,
        }
    ),
    IntegrationState.RUNTIME_STALE: frozenset(
        {
            IntegrationState.SERVICE_RESTART_REQUIRED,
            IntegrationState.DEPLOY_PENDING,
            IntegrationState.DEFER_WITH_OWNER,
        }
    ),
    IntegrationState.DELETE_PENDING: frozenset(
        {
            IntegrationState.DELIVERED,
            IntegrationState.DEFER_WITH_OWNER,
        }
    ),
    IntegrationState.RETIRE_PENDING: frozenset(
        {
            IntegrationState.DELIVERED,
            IntegrationState.DEFER_WITH_OWNER,
        }
    ),
    IntegrationState.DEFER_WITH_OWNER: frozenset(
        {
            IntegrationState.REVIEW_PENDING,
            IntegrationState.DELETE_PENDING,
            IntegrationState.RETIRE_PENDING,
            IntegrationState.SUPERSEDED,
        }
    ),
    IntegrationState.DELIVERED: frozenset(),
    IntegrationState.SUPERSEDED: frozenset(),
}


def _text(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TransitionError(f"{field} must be a non-empty string")
    return value.strip()


@dataclass(frozen=True)
class IntegrationItem:
    integration_id: str
    project_id: str
    run_id: str
    task_id: str
    state: IntegrationState
    source_ref: str
    target_ref: str
    owner: str
    evidence_refs: tuple[str, ...]
    updated_at: str


def _item(row: Mapping[str, Any]) -> IntegrationItem:
    return IntegrationItem(
        integration_id=row["integration_id"],
        project_id=row["project_id"],
        run_id=row["run_id"],
        task_id=row["task_id"],
        state=IntegrationState(row["state"]),
        source_ref=row["source_ref"],
        target_ref=row["target_ref"],
        owner=row["owner"],
        evidence_refs=tuple(json.loads(row["evidence_refs_json"])),
        updated_at=row["updated_at"],
    )


class IntegrationQueue:
    def __init__(
        self,
        store: SQLiteStore,
        *,
        policy_version: str = "companyos-policy-v1",
        identity: IdentityManager | None = None,
    ):
        self.store = store
        self.policy_version = policy_version
        self.identity = identity or IdentityManager(store)

    def _actor_id_in_transaction(
        self, connection: Any, actor: VerifiedPrincipal, *, roles: set[Role]
    ) -> str:
        principal = self.identity.verify_in_transaction(connection, actor)
        if not principal.roles.intersection(roles):
            raise TransitionError(
                "integration actor lacks the required authenticated role"
            )
        return principal.principal_id

    @staticmethod
    def _task(connection: Any, task_id: str) -> Mapping[str, Any]:
        row = connection.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"task not found: {task_id}")
        if row["run_id"] is None:
            raise TransitionError(f"task has no run: {task_id}")
        return row

    @staticmethod
    def _validate_evidence(
        connection: Any, task_id: str, refs: tuple[str, ...]
    ) -> None:
        if not refs:
            return
        placeholders = ",".join("?" for _ in refs)
        rows = connection.execute(
            f"SELECT evidence_id, task_id FROM evidence_claims WHERE evidence_id IN ({placeholders})",
            refs,
        ).fetchall()
        found = {row["evidence_id"] for row in rows}
        if found != set(refs):
            raise EvidenceError(
                f"integration evidence missing: {sorted(set(refs) - found)}"
            )
        if any(row["task_id"] != task_id for row in rows):
            raise EvidenceError("integration evidence belongs to another task")

    def create(
        self,
        *,
        task_id: str,
        source_ref: str,
        target_ref: str,
        owner: VerifiedPrincipal,
        initial_state: IntegrationState | str = IntegrationState.REVIEW_PENDING,
        evidence_refs: Iterable[str] = (),
        integration_id: str | None = None,
    ) -> IntegrationItem:
        task_id = _text(task_id, "task_id")
        source_ref = _text(source_ref, "source_ref")
        target_ref = _text(target_ref, "target_ref")
        try:
            state = IntegrationState(str(initial_state))
        except ValueError as exc:
            raise TransitionError(
                f"unsupported integration state: {initial_state}"
            ) from exc
        if state is not IntegrationState.REVIEW_PENDING:
            raise TransitionError(
                "new integration items must start at review_pending; import/rebuild requires a separate trusted path"
            )
        refs = tuple(dict.fromkeys(_text(ref, "evidence_ref") for ref in evidence_refs))
        integration_id = _text(integration_id or str(uuid.uuid4()), "integration_id")
        with self.store.transaction(immediate=True) as connection:
            owner_id = self._actor_id_in_transaction(
                connection, owner, roles={Role.RELEASE, Role.SYSTEM}
            )
            existing = connection.execute(
                "SELECT * FROM integration_items WHERE integration_id = ?",
                (integration_id,),
            ).fetchone()
            if existing is not None:
                record = _item(existing)
                expected = (task_id, source_ref, target_ref, owner_id, state, refs)
                actual = (
                    record.task_id,
                    record.source_ref,
                    record.target_ref,
                    record.owner,
                    record.state,
                    record.evidence_refs,
                )
                if actual != expected:
                    raise IntegrityError(
                        f"integration id reused with different content: {integration_id}"
                    )
                return record
            task = self._task(connection, task_id)
            task_state = TaskState(task["state"])
            if task_state in TERMINAL_TASK_STATES:
                raise TransitionError(
                    f"terminal task is sealed against new integration items: {task_id}"
                )
            run = connection.execute(
                "SELECT loop_state FROM runs WHERE run_id = ? AND project_id = ?",
                (task["run_id"], task["project_id"]),
            ).fetchone()
            if run is None:
                raise NotFoundError(f"run not found for task: {task_id}")
            if LoopState(run["loop_state"]) in {
                LoopState.DELIVERED,
                LoopState.IMPROVEMENT_PENDING,
            }:
                raise TransitionError(
                    f"delivered run is sealed against new integration items: {task['run_id']}"
                )
            self._validate_evidence(connection, task_id, refs)
            now = utc_now()
            payload = {
                "state": state.value,
                "source_ref": source_ref,
                "target_ref": target_ref,
                "owner": owner_id,
                "evidence_refs": list(refs),
            }
            self.store.append_event(
                connection,
                aggregate_type="integration",
                aggregate_id=integration_id,
                expected_version=0,
                project_id=task["project_id"],
                run_id=task["run_id"],
                task_id=task_id,
                event_type="integration_item_created",
                actor=owner_id,
                command_id=str(uuid.uuid4()),
                correlation_id=task["run_id"],
                policy_version=self.policy_version,
                payload=payload,
            )
            connection.execute(
                """
                INSERT INTO integration_items(
                    integration_id, project_id, run_id, task_id, state,
                    source_ref, target_ref, owner, evidence_refs_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    integration_id,
                    task["project_id"],
                    task["run_id"],
                    task_id,
                    state.value,
                    source_ref,
                    target_ref,
                    owner_id,
                    canonical_json(list(refs)),
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM integration_items WHERE integration_id = ?",
                (integration_id,),
            ).fetchone()
            return _item(row)

    def advance(
        self,
        integration_id: str,
        *,
        target: IntegrationState | str,
        actor: VerifiedPrincipal,
        evidence_refs: Iterable[str] = (),
        reason: str,
    ) -> IntegrationItem:
        integration_id = _text(integration_id, "integration_id")
        reason = _text(reason, "reason")
        try:
            target_state = IntegrationState(str(target))
        except ValueError as exc:
            raise TransitionError(f"unsupported integration state: {target}") from exc
        allowed_roles = {Role.RELEASE, Role.SYSTEM}
        if target_state in {
            IntegrationState.DELETE_PENDING,
            IntegrationState.RETIRE_PENDING,
        }:
            allowed_roles.add(Role.OWNER)
        refs = tuple(dict.fromkeys(_text(ref, "evidence_ref") for ref in evidence_refs))
        with self.store.transaction(immediate=True) as connection:
            actor_id = self._actor_id_in_transaction(
                connection, actor, roles=allowed_roles
            )
            row = connection.execute(
                "SELECT * FROM integration_items WHERE integration_id = ?",
                (integration_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"integration item not found: {integration_id}")
            task_lifecycle = connection.execute(
                "SELECT state FROM tasks WHERE task_id = ?", (row["task_id"],)
            ).fetchone()
            if task_lifecycle is None:
                raise IntegrityError("integration item references a missing task")
            if TaskState(task_lifecycle["state"]) in TERMINAL_TASK_STATES:
                raise TransitionError(
                    "terminal task is sealed against integration mutation"
                )
            current = IntegrationState(row["state"])
            if target_state not in _TRANSITIONS[current]:
                raise TransitionError(
                    f"integration transition not allowed: {current.value} -> {target_state.value}"
                )
            self._validate_evidence(connection, row["task_id"], refs)
            existing_refs = tuple(json.loads(row["evidence_refs_json"]))
            all_refs = tuple(dict.fromkeys((*existing_refs, *refs)))
            if target_state in _FINAL:
                from .policy import _required_decision_gates_satisfied

                if not _required_decision_gates_satisfied(connection, row["task_id"]):
                    raise TransitionError(
                        "compiled Task required decision gates are not satisfied"
                    )
                if not all_refs:
                    raise EvidenceError(
                        "final integration state requires evidence references"
                    )
                self._validate_evidence(connection, row["task_id"], all_refs)
                task = connection.execute(
                    "SELECT spec_json FROM tasks WHERE task_id = ?",
                    (row["task_id"],),
                ).fetchone()
                spec = TaskSpec.from_dict(json.loads(task["spec_json"]))
                accepted_verdicts = [
                    EvaluatorVerdict.PASS.value,
                    EvaluatorVerdict.PASS_WITH_RISK.value,
                ]
                if not spec.evaluator_required:
                    accepted_verdicts.append(EvaluatorVerdict.NOT_REQUIRED.value)
                placeholders = ",".join("?" for _ in all_refs)
                verdict_placeholders = ",".join("?" for _ in accepted_verdicts)
                passing = connection.execute(
                    f"SELECT 1 FROM evidence_claims WHERE evidence_id IN ({placeholders}) "
                    "AND task_id = ? AND evidence_state = ? "
                    f"AND evaluator_verdict IN ({verdict_placeholders}) LIMIT 1",
                    (
                        *all_refs,
                        row["task_id"],
                        spec.evidence_target.value,
                        *accepted_verdicts,
                    ),
                ).fetchone()
                if passing is None:
                    raise EvidenceError(
                        "final integration state requires passing task evidence"
                    )
            version_row = connection.execute(
                "SELECT COALESCE(MAX(aggregate_version), 0) AS version FROM events "
                "WHERE aggregate_type = 'integration' AND aggregate_id = ?",
                (integration_id,),
            ).fetchone()
            payload = {
                "from": current.value,
                "to": target_state.value,
                "reason": reason,
                "evidence_refs": list(refs),
            }
            self.store.append_event(
                connection,
                aggregate_type="integration",
                aggregate_id=integration_id,
                expected_version=int(version_row["version"]),
                project_id=row["project_id"],
                run_id=row["run_id"],
                task_id=row["task_id"],
                event_type="integration_state_changed",
                actor=actor_id,
                command_id=str(uuid.uuid4()),
                correlation_id=row["run_id"],
                policy_version=self.policy_version,
                payload=payload,
            )
            connection.execute(
                "UPDATE integration_items SET state = ?, evidence_refs_json = ?, updated_at = ? "
                "WHERE integration_id = ?",
                (
                    target_state.value,
                    canonical_json(list(all_refs)),
                    utc_now(),
                    integration_id,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM integration_items WHERE integration_id = ?",
                (integration_id,),
            ).fetchone()
            return _item(updated)

    def require_task_satisfied(
        self, task_id: str, *, allow_no_items: bool = False
    ) -> tuple[IntegrationItem, ...]:
        rows = self.store.query(
            "SELECT * FROM integration_items WHERE task_id = ? ORDER BY updated_at",
            (task_id,),
        )
        if not rows and not allow_no_items:
            raise TransitionError(f"task has no integration route: {task_id}")
        items = tuple(_item(row) for row in rows)
        incomplete = [item for item in items if item.state not in _FINAL]
        if incomplete:
            summary = ", ".join(
                f"{item.integration_id}:{item.state.value}" for item in incomplete
            )
            raise TransitionError(f"integration queue is not satisfied: {summary}")
        return items
