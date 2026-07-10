"""Golden and fail-closed tests for authoring-packet compilation."""

from __future__ import annotations

import unittest

from companyos_runtime.compiler import compile_goal, compile_task
from companyos_runtime.errors import ContractError
from companyos_runtime.types import Capability, EvidenceState, GoalSpec


class CompilerTests(unittest.TestCase):
    def test_authoring_packets_compile_to_stable_runtime_golden(self) -> None:
        goal_authoring = {
            "goal_contract": {
                "goal_id": "goal-golden",
                "target_outcome": "produce one verified local artifact",
                "success_evidence_states": ["runtime_verification"],
                "non_goals": ["provider_smoke", "public_release"],
                "owner_authority": {
                    "read_scope": ["workspace://project/public/**"],
                    "write_scope": ["workspace://project/output/**"],
                    "forbidden_scope": ["workspace://project/secrets/**"],
                    "allowed_capabilities": ["read_local", "repo_remote"],
                },
                "required_runtime_surfaces": [
                    {
                        "surface_key": "repo:local",
                        "target_identity": "commit:abc123",
                        "allowed_probes": ["git_head_probe"],
                        "max_ttl_seconds": 300,
                        "trigger_event_required": True,
                    }
                ],
                "evaluator_required": True,
                "circuit_breakers": {
                    "max_iterations_without_new_evidence": 4,
                    "provider_budget": {
                        "currency": "USD",
                        "max_minor_units": 0,
                        "max_calls": 0,
                    },
                },
                "closeout_shape": "owner_summary",
            }
        }
        goal, goal_result = compile_goal(goal_authoring)
        expected_goal = {
            "goal_id": "goal-golden",
            "target_outcome": "produce one verified local artifact",
            "success_evidence_states": ["runtime_verification"],
            "read_scope": ["workspace://project/public/**"],
            "write_scope": ["workspace://project/output/**"],
            "forbidden_scope": ["workspace://project/secrets/**"],
            "allowed_capabilities": ["read_local", "repo_remote"],
            "required_runtime_surfaces": [
                {
                    "surface_key": "repo:local",
                    "target_identity": "commit:abc123",
                    "allowed_probes": ["git_head_probe"],
                    "max_ttl_seconds": 300,
                    "trigger_event_required": True,
                }
            ],
            "evaluator_required": True,
            "max_iterations_without_evidence": 4,
            "provider_budget_minor_units": 0,
            "provider_call_limit": 0,
            "budget_currency": "USD",
            "non_goals": ["provider_smoke", "public_release"],
        }
        self.assertEqual(goal.to_dict(), expected_goal)
        self.assertEqual(goal_result.compiled, expected_goal)
        self.assertEqual(
            goal_result.non_executable_authoring_fields, ("closeout_shape",)
        )
        self.assertEqual(len(goal_result.source_digest), 64)

        task_authoring = {
            "task_packet": {
                "task_id": "task-golden",
                "parent_goal_id": "goal-golden",
                "objective": "read local input and prepare the integration artifact",
                "expected_delta": "integration",
                "primary_artifact_or_surface": "workspace://project/output/report.json",
                "read_scope": ["workspace://project/public/input.json"],
                "write_scope": ["workspace://project/output/report.json"],
                "forbidden_scope": ["workspace://project/secrets/**"],
                "capabilities": ["read_local", "repo_remote"],
                "gates": {"repo_remote": "scoped_open", "provider": "closed"},
                "evaluator_policy": "required_before_claim",
                "integration_required": True,
                "required_runtime_surfaces": [
                    {
                        "surface_key": "repo:local",
                        "target_identity": "commit:abc123",
                        "allowed_probes": ["git_head_probe"],
                        "max_ttl_seconds": 300,
                        "trigger_event_required": True,
                    }
                ],
                "workflow_steps": [
                    {
                        "step_id": "compile-report",
                        "adapter": "local",
                        "action": "write",
                        "resource": "workspace://project/output/report.json",
                        "request_digest": "a" * 64,
                    }
                ],
                "evidence_target": "runtime_verification",
                "max_attempts": 2,
                "procedure": ["orient", "execute", "verify"],
            }
        }
        task, task_result = compile_task(task_authoring, goal=goal)
        expected_task = {
            "task_id": "task-golden",
            "goal_id": "goal-golden",
            "objective": "read local input and prepare the integration artifact",
            "expected_delta": "integration",
            "primary_surface": "workspace://project/output/report.json",
            "evidence_target": "runtime_verification",
            "capabilities": ["read_local", "repo_remote"],
            "read_scope": ["workspace://project/public/input.json"],
            "write_scope": ["workspace://project/output/report.json"],
            "forbidden_scope": ["workspace://project/secrets/**"],
            "required_runtime_surfaces": [
                {
                    "surface_key": "repo:local",
                    "target_identity": "commit:abc123",
                    "allowed_probes": ["git_head_probe"],
                    "max_ttl_seconds": 300,
                    "trigger_event_required": True,
                }
            ],
            "evaluator_required": True,
            "integration_required": True,
            "workflow_steps": [
                {
                    "step_id": "compile-report",
                    "adapter": "local",
                    "action": "write",
                    "resource": "workspace://project/output/report.json",
                    "request_digest": "a" * 64,
                }
            ],
            "max_attempts": 2,
        }
        self.assertEqual(task.to_dict(), expected_task)
        self.assertEqual(task_result.compiled, expected_task)
        self.assertEqual(task_result.non_executable_authoring_fields, ("procedure",))
        self.assertEqual(len(task_result.source_digest), 64)

        _, repeated = compile_task(task_authoring, goal=goal)
        self.assertEqual(repeated.source_digest, task_result.source_digest)
        self.assertEqual(repeated.compiled, task_result.compiled)

    def test_open_gate_without_exact_capability_fails_closed(self) -> None:
        goal = GoalSpec(
            goal_id="goal-gates",
            target_outcome="exercise exact gate compilation",
            success_evidence_states=(EvidenceState.RUNTIME,),
            allowed_capabilities=tuple(Capability),
            provider_call_limit=1,
        )
        cases = {
            "repo_remote": "repo_remote",
            "server_write": "server_write",
            "provider": "provider_cost",
            "public_release": "public_release",
            "destructive_operations": "destructive",
        }
        for gate, capability in cases.items():
            packet = {
                "task_packet": {
                    "task_id": f"task-{gate}",
                    "parent_goal_id": "goal-gates",
                    "objective": "prove open gates cannot imply authority",
                    "expected_delta": "quality",
                    "primary_artifact_or_surface": f"surface://{gate}",
                    "evidence_target": "runtime_verification",
                    "capabilities": ["read_local"],
                    "gates": {gate: True},
                }
            }
            with self.subTest(gate=gate):
                with self.assertRaisesRegex(
                    ContractError,
                    f"gate {gate} is open but exact capability {capability} is absent",
                ):
                    compile_task(packet, goal=goal)

    def test_closed_gate_does_not_silently_add_capability(self) -> None:
        goal = GoalSpec(
            goal_id="goal-closed",
            target_outcome="retain closed provider gate",
            success_evidence_states=(EvidenceState.RUNTIME,),
            allowed_capabilities=(Capability.READ_LOCAL,),
        )
        task, _ = compile_task(
            {
                "task_packet": {
                    "task_id": "task-closed",
                    "parent_goal_id": "goal-closed",
                    "objective": "run without provider access",
                    "expected_delta": "quality",
                    "primary_artifact_or_surface": "local://report",
                    "evidence_target": "runtime_verification",
                    "capabilities": ["read_local"],
                    "gates": {"provider": "closed"},
                }
            },
            goal=goal,
        )
        self.assertEqual(task.capabilities, (Capability.READ_LOCAL,))

    def test_closed_gate_conflicting_with_capability_fails_closed(self) -> None:
        goal = GoalSpec(
            goal_id="goal-conflict",
            target_outcome="reject contradictory authority",
            success_evidence_states=(EvidenceState.RUNTIME,),
            allowed_capabilities=tuple(Capability),
            provider_call_limit=1,
        )
        packet = {
            "task_packet": {
                "task_id": "task-conflict",
                "parent_goal_id": "goal-conflict",
                "objective": "reject a closed provider gate with provider authority",
                "expected_delta": "quality",
                "primary_artifact_or_surface": "local://report",
                "evidence_target": "runtime_verification",
                "capabilities": ["read_local", "provider_cost"],
                "gates": {"provider": "closed"},
            }
        }
        with self.assertRaisesRegex(ContractError, "closed but capability"):
            compile_task(packet, goal=goal)

    def test_evaluator_policy_is_strict_and_cannot_be_overridden(self) -> None:
        goal = GoalSpec(
            goal_id="goal-evaluator",
            target_outcome="compile evaluator policy exactly",
            success_evidence_states=(EvidenceState.RUNTIME,),
        )
        base = {
            "task_id": "task-evaluator",
            "parent_goal_id": "goal-evaluator",
            "objective": "require an independent evaluator",
            "expected_delta": "quality",
            "primary_artifact_or_surface": "local://report",
            "evidence_target": "runtime_verification",
        }
        with self.assertRaisesRegex(ContractError, "evaluator_policy must be"):
            compile_task(
                {"task_packet": base | {"evaluator_policy": "requireed"}},
                goal=goal,
            )
        with self.assertRaisesRegex(ContractError, "contradicts evaluator_policy"):
            compile_task(
                {
                    "task_packet": base
                    | {
                        "evaluator_policy": "required_before_claim",
                        "evaluator_required": False,
                    }
                },
                goal=goal,
            )

    def test_network_and_external_download_gates_are_not_ignored(self) -> None:
        goal = GoalSpec(
            goal_id="goal-network",
            target_outcome="compile network authority exactly",
            success_evidence_states=(EvidenceState.RUNTIME,),
            allowed_capabilities=tuple(Capability),
            provider_call_limit=1,
        )
        for gate, capability in (
            ("network", "network"),
            ("external_download", "external_download"),
        ):
            packet = {
                "task_packet": {
                    "task_id": f"task-{gate}",
                    "parent_goal_id": "goal-network",
                    "objective": "reject an ungranted open gate",
                    "expected_delta": "quality",
                    "primary_artifact_or_surface": "local://report",
                    "evidence_target": "runtime_verification",
                    "capabilities": ["read_local"],
                    "gates": {gate: "open"},
                }
            }
            with self.subTest(gate=gate):
                with self.assertRaisesRegex(ContractError, capability):
                    compile_task(packet, goal=goal)

    def test_authority_and_circuit_breaker_typos_fail_closed(self) -> None:
        base = {
            "goal_id": "goal-typo",
            "target_outcome": "reject authority typos",
            "success_evidence_states": ["runtime_verification"],
        }
        with self.assertRaisesRegex(ContractError, "owner_authority"):
            compile_goal(
                {
                    "goal_contract": base
                    | {"owner_authority": {"forbidden_scop": ["server://prod"]}}
                }
            )
        with self.assertRaisesRegex(ContractError, "circuit_breakers"):
            compile_goal(
                {
                    "goal_contract": base
                    | {"circuit_breakers": {"cost_or_provider_limit": 0}}
                }
            )

    def test_unknown_task_authoring_field_fails_instead_of_warning(self) -> None:
        goal = GoalSpec(
            goal_id="goal-task-typo",
            target_outcome="reject task authority typos",
            success_evidence_states=(EvidenceState.RUNTIME,),
        )
        packet = {
            "task_packet": {
                "task_id": "task-typo",
                "parent_goal_id": "goal-task-typo",
                "objective": "reject misspelled capability fields",
                "expected_delta": "quality",
                "primary_artifact_or_surface": "local://report",
                "evidence_target": "runtime_verification",
                "capabilites": ["server_write"],
            }
        }
        with self.assertRaisesRegex(ContractError, "task_packet"):
            compile_task(packet, goal=goal)

    def test_boolean_retry_limits_fail_before_schema_serialization(self) -> None:
        with self.assertRaisesRegex(ContractError, "positive integer"):
            compile_goal(
                {
                    "goal_contract": {
                        "goal_id": "goal-bool-limit",
                        "target_outcome": "reject bool-as-int ambiguity",
                        "success_evidence_states": ["runtime_verification"],
                        "circuit_breakers": {
                            "max_iterations_without_new_evidence": True
                        },
                    }
                }
            )
        goal = GoalSpec(
            goal_id="goal-task-bool-limit",
            target_outcome="reject bool task attempts",
            success_evidence_states=(EvidenceState.RUNTIME,),
        )
        with self.assertRaisesRegex(ContractError, "positive integer"):
            compile_task(
                {
                    "task_packet": {
                        "task_id": "task-bool-limit",
                        "parent_goal_id": goal.goal_id,
                        "objective": "reject bool-as-int ambiguity",
                        "expected_delta": "contract integrity",
                        "primary_artifact_or_surface": "local://report",
                        "evidence_target": "runtime_verification",
                        "max_attempts": True,
                    }
                },
                goal=goal,
            )


if __name__ == "__main__":
    unittest.main()
