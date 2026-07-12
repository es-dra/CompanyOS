"""Authoritative guard resolution from persisted runtime facts."""

from __future__ import annotations

import json
from typing import Any, Mapping

from .errors import ContractError
from .scope import validate_goal_scope, validate_task_within_goal
from .state_machine import LOOP_TRANSITIONS
from .types import (
    Capability,
    EvaluatorVerdict,
    GoalSpec,
    IntegrationState,
    LoopEvent,
    LoopState,
    TaskSpec,
    TaskState,
)


_PASSING_EVIDENCE = {
    EvaluatorVerdict.NOT_REQUIRED.value,
    EvaluatorVerdict.PASS.value,
    EvaluatorVerdict.PASS_WITH_RISK.value,
}
_PASSING_EVALUATOR = {
    EvaluatorVerdict.PASS.value,
    EvaluatorVerdict.PASS_WITH_RISK.value,
}
_INTEGRATION_FINAL = {
    IntegrationState.DELIVERED.value,
    IntegrationState.SUPERSEDED.value,
}
_HEALTHY = {"healthy", "ok", "pass"}
_DECISION_GATE_CAPABILITIES = {
    "provider": Capability.PROVIDER_COST.value,
    "merge": Capability.REPO_REMOTE.value,
    "release": Capability.PUBLIC_RELEASE.value,
}


def _decision_gates_satisfied(connection: Any, task_id: str) -> bool:
    row = connection.execute(
        "SELECT required_decision_gates_json FROM task_authority_bindings WHERE task_id = ?",
        (task_id,),
    ).fetchone()
    if row is None:
        return True
    for gate in json.loads(row["required_decision_gates_json"]):
        capability = _DECISION_GATE_CAPABILITIES.get(gate)
        clause = "capability = ?" if capability is not None else "action = ?"
        value = capability if capability is not None else gate
        if connection.execute(
            f"SELECT 1 FROM approvals WHERE task_id = ? AND {clause} "
            "AND decision = 'approved' AND julianday(expires_at) > julianday('now') LIMIT 1",
            (task_id, value),
        ).fetchone() is None:
            return False
    return True


class GuardResolver:
    """Computes transition guards; caller booleans are never authority."""

    def resolve(
        self,
        connection: Any,
        *,
        run: Mapping[str, Any],
        event: LoopEvent,
        payload: Mapping[str, Any],
        command_actor: str,
    ) -> dict[str, bool]:
        current = LoopState(run["loop_state"])
        rule = LOOP_TRANSITIONS.get((current, event))
        if rule is None:
            return {}
        return {
            name: self._resolve_one(
                connection,
                run=run,
                name=name,
                payload=payload,
                command_actor=command_actor,
            )
            for name in rule.guards
        }

    def _resolve_one(
        self,
        connection: Any,
        *,
        run: Mapping[str, Any],
        name: str,
        payload: Mapping[str, Any],
        command_actor: str,
    ) -> bool:
        if name in {"contract_valid", "readiness_gate_passed"}:
            return self._contract_valid(connection, run)
        if name == "lease_valid":
            return self._lease_valid(connection, run, payload, command_actor)
        if name in {"approval_valid", "resume_authorized", "owner_decision_recorded"}:
            return self._resume_approval_valid(connection, run, payload)
        if name == "evidence_satisfied":
            return self._evidence_status(connection, run, payload)[0]
        if name == "evaluator_satisfied":
            return self._evidence_status(connection, run, payload)[1]
        if name == "integration_satisfied":
            return self._integration_satisfied(connection, run)
        if name == "freshness_satisfied":
            return self._freshness_satisfied(connection, run)
        if name == "tasks_terminal":
            return self._tasks_terminal(connection, run)
        if name == "ci_green":
            return self._ci_green(connection, run, payload)
        if name == "repair_route_selected":
            return self._repair_route_selected(connection, run, payload)
        if name == "capability_available":
            return self._capability_available(connection, run, payload)
        if name == "improvement_routed":
            return (
                connection.execute(
                    "SELECT 1 FROM improvement_proposals WHERE source_run_id = ? LIMIT 1",
                    (run["run_id"],),
                ).fetchone()
                is not None
            )
        raise ContractError(f"no authoritative resolver exists for guard: {name}")

    @staticmethod
    def _goal(connection: Any, run: Mapping[str, Any]) -> GoalSpec:
        row = connection.execute(
            "SELECT spec_json FROM goals WHERE goal_id = ? AND project_id = ?",
            (run["goal_id"], run["project_id"]),
        ).fetchone()
        if row is None:
            raise ContractError("run goal projection is missing")
        return GoalSpec.from_dict(json.loads(row["spec_json"]))

    def _task_rows(
        self, connection: Any, run: Mapping[str, Any], payload: Mapping[str, Any]
    ) -> list[Any]:
        task_id = payload.get("task_id")
        if task_id is not None:
            if not isinstance(task_id, str) or not task_id:
                return []
            rows = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ? AND run_id = ? AND project_id = ?",
                (task_id, run["run_id"], run["project_id"]),
            ).fetchall()
            return list(rows)
        return list(
            connection.execute(
                "SELECT * FROM tasks WHERE run_id = ? AND project_id = ? ORDER BY task_id",
                (run["run_id"], run["project_id"]),
            ).fetchall()
        )

    def _contract_valid(self, connection: Any, run: Mapping[str, Any]) -> bool:
        try:
            goal = self._goal(connection, run)
            validate_goal_scope(goal)
            tasks = self._task_rows(connection, run, {})
            if not tasks:
                return False
            task_targets = set()
            for row in tasks:
                task = TaskSpec.from_dict(json.loads(row["spec_json"]))
                validate_task_within_goal(goal, task)
                task_targets.add(task.evidence_target)
            return set(goal.success_evidence_states).issubset(task_targets)
        except Exception:
            return False

    @staticmethod
    def _lease_valid(
        connection: Any,
        run: Mapping[str, Any],
        payload: Mapping[str, Any],
        command_actor: str,
    ) -> bool:
        required = ("task_id", "resource_key", "holder", "fence")
        if any(key not in payload for key in required):
            return False
        if payload["holder"] != command_actor:
            return False
        return (
            connection.execute(
                """
            SELECT 1
            FROM leases AS l
            JOIN tasks AS t ON t.task_id = l.task_id
            WHERE l.task_id = ? AND l.project_id = ? AND l.resource_key = ?
              AND l.holder = ? AND l.fence = ? AND l.released_at IS NULL
              AND t.project_id = ? AND t.run_id = ?
              AND julianday(l.expires_at) > julianday('now')
            """,
                (
                    payload["task_id"],
                    run["project_id"],
                    payload["resource_key"],
                    command_actor,
                    payload["fence"],
                    run["project_id"],
                    run["run_id"],
                ),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _resume_approval_valid(
        connection: Any, run: Mapping[str, Any], payload: Mapping[str, Any]
    ) -> bool:
        approval_id = payload.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id:
            return False
        return (
            connection.execute(
                """
            SELECT 1 FROM approvals
            WHERE approval_id = ? AND project_id = ? AND run_id = ?
              AND capability = ? AND action = 'resume_run' AND resource = ?
              AND decision = 'approved' AND julianday(expires_at) > julianday('now')
            """,
                (
                    approval_id,
                    run["project_id"],
                    run["run_id"],
                    Capability.CONTROL_RESUME.value,
                    f"run:{run['run_id']}",
                ),
            ).fetchone()
            is not None
        )

    def _evidence_status(
        self, connection: Any, run: Mapping[str, Any], payload: Mapping[str, Any]
    ) -> tuple[bool, bool]:
        # Evidence/evaluator transitions are run-level decisions. A task_id in
        # an event payload is context only and must never narrow finalization.
        tasks = self._task_rows(connection, run, {})
        if not tasks:
            return False, False
        goal = self._goal(connection, run)
        evidence_ok = True
        evaluator_ok = True
        passing_goal_states: set[str] = set()
        independently_passing_goal_states: set[str] = set()
        for task in tasks:
            spec = TaskSpec.from_dict(json.loads(task["spec_json"]))
            claims = connection.execute(
                "SELECT evaluator_verdict FROM evidence_claims "
                "WHERE task_id = ? AND evidence_state = ?",
                (task["task_id"], spec.evidence_target.value),
            ).fetchall()
            evidence_ok = evidence_ok and any(
                claim["evaluator_verdict"] in _PASSING_EVIDENCE for claim in claims
            )
            evaluator_ok = evaluator_ok and (
                not spec.evaluator_required
                or any(
                    claim["evaluator_verdict"] in _PASSING_EVALUATOR for claim in claims
                )
            )
            if any(claim["evaluator_verdict"] in _PASSING_EVIDENCE for claim in claims):
                passing_goal_states.add(spec.evidence_target.value)
            if any(
                claim["evaluator_verdict"] in _PASSING_EVALUATOR for claim in claims
            ):
                independently_passing_goal_states.add(spec.evidence_target.value)
        required_goal_states = {item.value for item in goal.success_evidence_states}
        evidence_ok = evidence_ok and required_goal_states.issubset(passing_goal_states)
        if goal.evaluator_required:
            evaluator_ok = evaluator_ok and required_goal_states.issubset(
                independently_passing_goal_states
            )
        return evidence_ok, evaluator_ok

    def _tasks_terminal(self, connection: Any, run: Mapping[str, Any]) -> bool:
        tasks = self._task_rows(connection, run, {})
        if not tasks:
            return False
        # v0.2 has no optional/superseded TaskSpec semantic. Cancellation,
        # deletion, failure, or retirement therefore cannot prove successful
        # Run delivery; every declared task must pass its own delivery gate.
        return all(
            task["state"] == TaskState.DELIVERED.value
            and _decision_gates_satisfied(connection, task["task_id"])
            for task in tasks
        )

    def _integration_satisfied(self, connection: Any, run: Mapping[str, Any]) -> bool:
        tasks = self._task_rows(connection, run, {})
        if not tasks:
            return False
        for task in tasks:
            if not _decision_gates_satisfied(connection, task["task_id"]):
                return False
            spec = TaskSpec.from_dict(json.loads(task["spec_json"]))
            if not spec.integration_required:
                continue
            states = connection.execute(
                "SELECT state FROM integration_items WHERE task_id = ?",
                (task["task_id"],),
            ).fetchall()
            if not states or any(
                item["state"] not in _INTEGRATION_FINAL for item in states
            ):
                return False
        return True

    def _freshness_satisfied(self, connection: Any, run: Mapping[str, Any]) -> bool:
        goal = self._goal(connection, run)
        for requirement in goal.required_runtime_surfaces:
            surface = requirement.surface_key
            rows = connection.execute(
                "SELECT * FROM runtime_observations WHERE run_id = ? AND surface_key = ? "
                "ORDER BY observed_at DESC, recorded_at DESC",
                (run["run_id"], surface),
            ).fetchall()
            if not rows:
                return False
            latest = rows[0]
            if latest["status"] not in _HEALTHY:
                return False
            if latest["target_identity"] != requirement.target_identity:
                return False
            if latest["probe_name"] not in requirement.allowed_probes:
                return False
            if (
                requirement.trigger_event_required
                and latest["trigger_event_id"] is None
            ):
                return False
            if latest["trigger_event_id"] is not None:
                trigger = connection.execute(
                    "SELECT 1 FROM events WHERE event_id = ? AND run_id = ?",
                    (latest["trigger_event_id"], run["run_id"]),
                ).fetchone()
                if trigger is None:
                    return False
            observer = connection.execute(
                "SELECT 1 FROM principals AS p JOIN principal_roles AS r "
                "ON r.principal_id = p.principal_id "
                "WHERE p.principal_id = ? AND p.enabled = 1 AND r.role = ?",
                (latest["observer"], "observer"),
            ).fetchone()
            if observer is None:
                return False
            ttl_ok = connection.execute(
                "SELECT CAST(strftime('%s', ?) AS INTEGER) "
                "- CAST(strftime('%s', ?) AS INTEGER) BETWEEN 0 AND ?",
                (
                    latest["expires_at"],
                    latest["observed_at"],
                    requirement.max_ttl_seconds,
                ),
            ).fetchone()[0]
            if ttl_ok != 1:
                return False
            fresh = connection.execute(
                "SELECT julianday(?) <= julianday('now') AND julianday(?) > julianday('now')",
                (latest["observed_at"], latest["expires_at"]),
            ).fetchone()[0]
            if fresh != 1:
                return False
            signatures = {
                (item["target_identity"], item["status"], item["value_digest"])
                for item in rows
                if item["observed_at"] == latest["observed_at"]
            }
            if len(signatures) != 1:
                return False
        return True

    @staticmethod
    def _ci_green(
        connection: Any, run: Mapping[str, Any], payload: Mapping[str, Any]
    ) -> bool:
        integration_id = payload.get("integration_id")
        if not isinstance(integration_id, str):
            return False
        return (
            connection.execute(
                "SELECT 1 FROM integration_items WHERE integration_id = ? AND run_id = ? "
                "AND state IN ('merge_pending', 'deploy_pending', 'delivered')",
                (integration_id, run["run_id"]),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _repair_route_selected(
        connection: Any, run: Mapping[str, Any], payload: Mapping[str, Any]
    ) -> bool:
        task_id = payload.get("task_id")
        if not isinstance(task_id, str):
            return False
        return (
            connection.execute(
                "SELECT 1 FROM negative_results WHERE task_id = ? AND run_id = ? "
                "AND length(repair_route) > 0",
                (task_id, run["run_id"]),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _capability_available(
        connection: Any, run: Mapping[str, Any], payload: Mapping[str, Any]
    ) -> bool:
        grant_id = payload.get("grant_id")
        if not isinstance(grant_id, str):
            return False
        return (
            connection.execute(
                """
            SELECT 1 FROM capability_grants
            WHERE grant_id = ? AND run_id = ? AND revoked_at IS NULL
              AND julianday(not_before) <= julianday('now')
              AND julianday(expires_at) > julianday('now')
              AND used_count < max_uses AND cost_used <= cost_limit
            """,
                (grant_id, run["run_id"]),
            ).fetchone()
            is not None
        )
