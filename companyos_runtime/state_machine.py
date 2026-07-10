"""Code-enforced run/task transitions and the immutable goal projection."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from .errors import TransitionError
from .types import GoalState, LoopEvent, LoopState, TaskState


@dataclass(frozen=True)
class LoopTransitionRule:
    target: LoopState
    guards: tuple[str, ...] = ()


LOOP_TRANSITIONS: Mapping[tuple[LoopState, LoopEvent], LoopTransitionRule] = {
    (LoopState.INTAKE, LoopEvent.GOAL_COMPILED): LoopTransitionRule(
        LoopState.COMPILED, ("contract_valid",)
    ),
    (LoopState.INTAKE, LoopEvent.MISSING_STATE_DETECTED): LoopTransitionRule(
        LoopState.BLOCKED_MISSING_STATE
    ),
    (LoopState.COMPILED, LoopEvent.RUN_READY): LoopTransitionRule(
        LoopState.READY, ("readiness_gate_passed",)
    ),
    (LoopState.COMPILED, LoopEvent.CAPABILITY_GAP_DETECTED): LoopTransitionRule(
        LoopState.BLOCKED_CAPABILITY
    ),
    (LoopState.READY, LoopEvent.TASK_STARTED): LoopTransitionRule(
        LoopState.RUNNING, ("lease_valid",)
    ),
    (LoopState.READY, LoopEvent.CAPABILITY_GAP_DETECTED): LoopTransitionRule(
        LoopState.BLOCKED_CAPABILITY
    ),
    (LoopState.RUNNING, LoopEvent.HUMAN_APPROVAL_REQUESTED): LoopTransitionRule(
        LoopState.SUSPENDED
    ),
    (LoopState.RUNNING, LoopEvent.EVIDENCE_SUBMITTED): LoopTransitionRule(
        LoopState.EVIDENCE_PENDING
    ),
    (LoopState.RUNNING, LoopEvent.CIRCUIT_BREAKER_TRIGGERED): LoopTransitionRule(
        LoopState.BLOCKED_DECISION
    ),
    (LoopState.RUNNING, LoopEvent.CAPABILITY_GAP_DETECTED): LoopTransitionRule(
        LoopState.BLOCKED_CAPABILITY
    ),
    (LoopState.SUSPENDED, LoopEvent.HUMAN_APPROVAL_RECEIVED): LoopTransitionRule(
        LoopState.RUNNING, ("approval_valid",)
    ),
    (LoopState.SUSPENDED, LoopEvent.RESUME_REQUESTED): LoopTransitionRule(
        LoopState.RUNNING, ("resume_authorized",)
    ),
    (
        LoopState.EVIDENCE_PENDING,
        LoopEvent.EVALUATOR_VERDICT_RECEIVED,
    ): LoopTransitionRule(
        LoopState.INTEGRATION_PENDING, ("evidence_satisfied", "evaluator_satisfied")
    ),
    (LoopState.EVIDENCE_PENDING, LoopEvent.TASK_STARTED): LoopTransitionRule(
        LoopState.RUNNING, ("repair_route_selected",)
    ),
    (LoopState.INTEGRATION_PENDING, LoopEvent.CI_CHECK_STARTED): LoopTransitionRule(
        LoopState.CI_PENDING
    ),
    (
        LoopState.INTEGRATION_PENDING,
        LoopEvent.DEPLOY_DIRECTORY_UPDATED,
    ): LoopTransitionRule(LoopState.DEPLOY_DIR_UPDATED),
    (LoopState.INTEGRATION_PENDING, LoopEvent.DELIVERY_CONFIRMED): LoopTransitionRule(
        LoopState.DELIVERED,
        (
            "evidence_satisfied",
            "evaluator_satisfied",
            "integration_satisfied",
            "freshness_satisfied",
            "tasks_terminal",
        ),
    ),
    (LoopState.CI_PENDING, LoopEvent.CI_CHECK_COMPLETED): LoopTransitionRule(
        LoopState.INTEGRATION_PENDING, ("ci_green",)
    ),
    (LoopState.CI_PENDING, LoopEvent.CIRCUIT_BREAKER_TRIGGERED): LoopTransitionRule(
        LoopState.BLOCKED_DECISION
    ),
    (
        LoopState.DEPLOY_DIR_UPDATED,
        LoopEvent.SERVICE_RESTART_ATTEMPTED,
    ): LoopTransitionRule(LoopState.RUNTIME_CHECK_PENDING),
    (
        LoopState.DEPLOY_DIR_UPDATED,
        LoopEvent.RUNTIME_DRIFT_DETECTED,
    ): LoopTransitionRule(LoopState.RUNTIME_STALE),
    (LoopState.RUNTIME_STALE, LoopEvent.SERVICE_RESTART_ATTEMPTED): LoopTransitionRule(
        LoopState.RUNTIME_CHECK_PENDING
    ),
    (
        LoopState.RUNTIME_CHECK_PENDING,
        LoopEvent.RUNTIME_FRESHNESS_VERIFIED,
    ): LoopTransitionRule(LoopState.RUNTIME_FRESH, ("freshness_satisfied",)),
    (
        LoopState.RUNTIME_CHECK_PENDING,
        LoopEvent.RUNTIME_DRIFT_DETECTED,
    ): LoopTransitionRule(LoopState.RUNTIME_STALE),
    (LoopState.RUNTIME_FRESH, LoopEvent.DELIVERY_CONFIRMED): LoopTransitionRule(
        LoopState.DELIVERED,
        (
            "evidence_satisfied",
            "evaluator_satisfied",
            "integration_satisfied",
            "freshness_satisfied",
            "tasks_terminal",
        ),
    ),
    (LoopState.DELIVERED, LoopEvent.IMPROVEMENT_REQUESTED): LoopTransitionRule(
        LoopState.IMPROVEMENT_PENDING
    ),
    (
        LoopState.BLOCKED_MISSING_STATE,
        LoopEvent.OWNER_INTENT_RECEIVED,
    ): LoopTransitionRule(LoopState.INTAKE),
    (LoopState.BLOCKED_CAPABILITY, LoopEvent.RESUME_REQUESTED): LoopTransitionRule(
        LoopState.READY, ("capability_available",)
    ),
    (LoopState.BLOCKED_DECISION, LoopEvent.RESUME_REQUESTED): LoopTransitionRule(
        LoopState.READY, ("owner_decision_recorded",)
    ),
    (LoopState.IMPROVEMENT_PENDING, LoopEvent.DELIVERY_CONFIRMED): LoopTransitionRule(
        LoopState.DELIVERED, ("improvement_routed",)
    ),
}


def apply_loop_event(
    current: LoopState,
    event: LoopEvent,
    guard_results: Mapping[str, bool] | None = None,
) -> LoopState:
    rule = LOOP_TRANSITIONS.get((current, event))
    if rule is None:
        raise TransitionError(
            f"loop event not allowed: {current.value} + {event.value}"
        )
    results = guard_results or {}
    failed = [guard for guard in rule.guards if results.get(guard) is not True]
    if failed:
        raise TransitionError(f"loop transition guards failed: {failed}")
    return rule.target


GOAL_TRANSITIONS: Mapping[GoalState, frozenset[GoalState]] = {
    # A Goal row is the immutable projection of one accepted compiled GoalSpec.
    # Executable progress belongs to Run and Task state machines. Aggregate
    # multi-run goal completion semantics are intentionally not invented here.
    GoalState.COMPILED: frozenset(),
}


TASK_TRANSITIONS: Mapping[TaskState, frozenset[TaskState]] = {
    TaskState.READY: frozenset(
        {TaskState.LEASED, TaskState.CANCELED, TaskState.BLOCKED, TaskState.DELETED}
    ),
    TaskState.LEASED: frozenset(
        {TaskState.RUNNING, TaskState.READY, TaskState.RETRY_PENDING, TaskState.BLOCKED}
    ),
    TaskState.RUNNING: frozenset(
        {
            TaskState.SUSPENDED,
            TaskState.EVIDENCE_PENDING,
            TaskState.RETRY_PENDING,
            TaskState.FAILED,
            TaskState.BLOCKED,
        }
    ),
    TaskState.SUSPENDED: frozenset(
        {TaskState.LEASED, TaskState.CANCELED, TaskState.BLOCKED}
    ),
    TaskState.EVIDENCE_PENDING: frozenset(
        {
            TaskState.EVALUATOR_PENDING,
            TaskState.INTEGRATION_PENDING,
            TaskState.RUNNING,
            TaskState.BLOCKED,
        }
    ),
    TaskState.EVALUATOR_PENDING: frozenset(
        {TaskState.INTEGRATION_PENDING, TaskState.RUNNING, TaskState.BLOCKED}
    ),
    TaskState.INTEGRATION_PENDING: frozenset(
        {TaskState.DELIVERED, TaskState.RUNNING, TaskState.BLOCKED}
    ),
    TaskState.RETRY_PENDING: frozenset(
        {TaskState.READY, TaskState.FAILED, TaskState.BLOCKED}
    ),
    TaskState.BLOCKED: frozenset(
        {TaskState.READY, TaskState.CANCELED, TaskState.DELETED, TaskState.RETIRED}
    ),
    TaskState.DELIVERED: frozenset({TaskState.RETIRED}),
    TaskState.FAILED: frozenset({TaskState.RETRY_PENDING, TaskState.RETIRED}),
    TaskState.CANCELED: frozenset({TaskState.RETIRED}),
    TaskState.DELETED: frozenset(),
    TaskState.RETIRED: frozenset(),
}


def require_transition(current: StrEnum, target: StrEnum) -> None:
    if type(current) is not type(target):
        raise TransitionError(
            f"state types differ: {type(current).__name__} -> {type(target).__name__}"
        )
    if isinstance(current, LoopState):
        raise TransitionError(
            "LoopState transitions require apply_loop_event with an explicit LoopEvent"
        )
    if isinstance(current, GoalState):
        if not isinstance(target, GoalState) or target not in GOAL_TRANSITIONS[current]:
            raise TransitionError(
                f"transition not allowed: {current.value} -> {target.value}"
            )
        return
    elif isinstance(current, TaskState):
        if not isinstance(target, TaskState) or target not in TASK_TRANSITIONS[current]:
            raise TransitionError(
                f"transition not allowed: {current.value} -> {target.value}"
            )
        return
    else:
        raise TransitionError(f"unsupported state type: {type(current).__name__}")
