"""Evaluator coverage for the code-enforced CompanyOS state machines."""

from __future__ import annotations

import unittest
from enum import StrEnum

from companyos_runtime.errors import TransitionError
from companyos_runtime.state_machine import (
    GOAL_TRANSITIONS,
    LOOP_TRANSITIONS,
    TASK_TRANSITIONS,
    apply_loop_event,
    require_transition,
)
from companyos_runtime.types import GoalState, LoopEvent, LoopState, TaskState


class LoopStateMachineTests(unittest.TestCase):
    def test_nominal_event_driven_loop_reaches_delivery(self) -> None:
        state = LoopState.INTAKE
        path = (
            (LoopEvent.GOAL_COMPILED, {"contract_valid": True}, LoopState.COMPILED),
            (LoopEvent.RUN_READY, {"readiness_gate_passed": True}, LoopState.READY),
            (LoopEvent.TASK_STARTED, {"lease_valid": True}, LoopState.RUNNING),
            (LoopEvent.HUMAN_APPROVAL_REQUESTED, {}, LoopState.SUSPENDED),
            (
                LoopEvent.HUMAN_APPROVAL_RECEIVED,
                {"approval_valid": True},
                LoopState.RUNNING,
            ),
            (LoopEvent.EVIDENCE_SUBMITTED, {}, LoopState.EVIDENCE_PENDING),
            (
                LoopEvent.EVALUATOR_VERDICT_RECEIVED,
                {"evidence_satisfied": True, "evaluator_satisfied": True},
                LoopState.INTEGRATION_PENDING,
            ),
            (
                LoopEvent.DELIVERY_CONFIRMED,
                {
                    "evidence_satisfied": True,
                    "evaluator_satisfied": True,
                    "integration_satisfied": True,
                    "freshness_satisfied": True,
                    "tasks_terminal": True,
                },
                LoopState.DELIVERED,
            ),
        )

        for event, guards, expected in path:
            with self.subTest(state=state, event=event):
                state = apply_loop_event(state, event, guards)
                self.assertIs(state, expected)

    def test_every_declared_loop_transition_reaches_its_target(self) -> None:
        for (current, event), rule in LOOP_TRANSITIONS.items():
            guards = {guard: True for guard in rule.guards}
            with self.subTest(current=current, event=event):
                self.assertIs(apply_loop_event(current, event, guards), rule.target)

    def test_every_required_guard_fails_closed_when_missing_or_false(self) -> None:
        guarded_rules = [
            (current, event, rule)
            for (current, event), rule in LOOP_TRANSITIONS.items()
            if rule.guards
        ]
        self.assertTrue(guarded_rules, "the loop must contain guarded transitions")

        for current, event, rule in guarded_rules:
            for missing_guard in rule.guards:
                other_guards = {
                    guard: True for guard in rule.guards if guard != missing_guard
                }
                with self.subTest(current=current, event=event, missing=missing_guard):
                    with self.assertRaisesRegex(TransitionError, missing_guard):
                        apply_loop_event(current, event, other_guards)

                false_guard = {guard: True for guard in rule.guards}
                false_guard[missing_guard] = False
                with self.subTest(current=current, event=event, false=missing_guard):
                    with self.assertRaisesRegex(TransitionError, missing_guard):
                        apply_loop_event(current, event, false_guard)

    def test_guard_values_must_be_literal_true(self) -> None:
        with self.assertRaisesRegex(TransitionError, "contract_valid"):
            apply_loop_event(
                LoopState.INTAKE,
                LoopEvent.GOAL_COMPILED,
                {"contract_valid": 1},
            )

    def test_all_undeclared_loop_state_event_pairs_are_forbidden(self) -> None:
        checked = 0
        for current in LoopState:
            for event in LoopEvent:
                if (current, event) in LOOP_TRANSITIONS:
                    continue
                checked += 1
                with self.subTest(current=current, event=event):
                    with self.assertRaisesRegex(
                        TransitionError, "loop event not allowed"
                    ):
                        apply_loop_event(current, event, {})
        self.assertGreater(checked, 0)

    def test_direct_delivery_and_terminal_restart_are_forbidden(self) -> None:
        with self.assertRaises(TransitionError):
            apply_loop_event(LoopState.INTAKE, LoopEvent.DELIVERY_CONFIRMED, {})
        with self.assertRaises(TransitionError):
            apply_loop_event(LoopState.DELIVERED, LoopEvent.TASK_STARTED, {})


class ProjectionStateMachineTests(unittest.TestCase):
    def test_goal_projection_exposes_only_immutable_compiled_state(self) -> None:
        self.assertEqual(tuple(GoalState), (GoalState.COMPILED,))
        self.assertEqual(
            GOAL_TRANSITIONS,
            {GoalState.COMPILED: frozenset()},
        )
        with self.assertRaisesRegex(TransitionError, "transition not allowed"):
            require_transition(GoalState.COMPILED, GoalState.COMPILED)

    def test_every_declared_goal_and_task_projection_transition_is_allowed(
        self,
    ) -> None:
        for transitions in (GOAL_TRANSITIONS, TASK_TRANSITIONS):
            for current, targets in transitions.items():
                for target in targets:
                    with self.subTest(current=current, target=target):
                        require_transition(current, target)

    def test_every_undeclared_goal_and_task_projection_transition_is_forbidden(
        self,
    ) -> None:
        for states, transitions in (
            (tuple(GoalState), GOAL_TRANSITIONS),
            (tuple(TaskState), TASK_TRANSITIONS),
        ):
            for current in states:
                for target in states:
                    if target in transitions[current]:
                        continue
                    with self.subTest(current=current, target=target):
                        with self.assertRaisesRegex(
                            TransitionError, "transition not allowed"
                        ):
                            require_transition(current, target)

    def test_projection_rejects_different_state_enum_types(self) -> None:
        with self.assertRaisesRegex(TransitionError, "state types differ"):
            require_transition(GoalState.COMPILED, TaskState.READY)
        with self.assertRaisesRegex(TransitionError, "state types differ"):
            require_transition(TaskState.READY, GoalState.COMPILED)

    def test_loop_projection_requires_an_explicit_event(self) -> None:
        with self.assertRaisesRegex(TransitionError, "explicit LoopEvent"):
            require_transition(LoopState.INTAKE, LoopState.COMPILED)

    def test_unknown_projection_state_type_is_rejected(self) -> None:
        class ForeignState(StrEnum):
            READY = "ready"

        with self.assertRaisesRegex(TransitionError, "unsupported state type"):
            require_transition(ForeignState.READY, ForeignState.READY)


if __name__ == "__main__":
    unittest.main()
