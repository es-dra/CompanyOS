"""Contract and negative-path tests for the Project/Program authority spine."""

from __future__ import annotations

import json
import copy
import tempfile
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, RefResolver  # type: ignore[import-untyped]

from companyos_runtime.authority import (
    CompiledGoalAuthority,
    CompiledTaskAuthority,
    ProgramSpec,
    ProgramState,
    ProjectSpec,
)
from companyos_runtime.authority_compiler import (
    compile_goal_authority,
    compile_program,
    compile_project,
    compile_task_authority,
    validate_program_graph,
)
from companyos_runtime.errors import AuthorizationError, ContractError, IntegrityError
from companyos_runtime.evidence import EvidenceRegistry
from companyos_runtime.integration import IntegrationQueue
from companyos_runtime.kernel import RuntimeKernel
from companyos_runtime.observations import ObservationRegistry
from companyos_runtime.policy import PolicyEngine, _required_decision_gates_satisfied
from companyos_runtime.replay import ProjectionReplayer
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import (
    Capability,
    EvidenceState,
    EvaluatorVerdict,
    IntegrationState,
    canonical_json,
    content_hash,
)
from tests.identity_fixtures import IdentityFixture


ROOT = Path(__file__).resolve().parents[1]
SURFACE = {
    "surface_key": "repo:afs",
    "target_identity": "commit:abc123",
    "allowed_probes": ["git-head"],
    "max_ttl_seconds": 300,
    "trigger_event_required": True,
}


def authority(
    *,
    capabilities: list[str] | None = None,
    read_scope: list[str] | None = None,
    write_scope: list[str] | None = None,
    surfaces: list[dict[str, object]] | None = None,
    budget: int = 10_000,
    calls: int = 10,
    evaluator: bool = True,
    gates: list[str] | None = None,
) -> dict[str, object]:
    return {
        "capabilities": capabilities
        or [
            "read_local",
            "write_local",
            "provider_cost",
            "repo_remote",
            "public_release",
        ],
        "read_scope": read_scope or ["repo://afs/**"],
        "write_scope": write_scope
        or [
            "repo://afs/worktrees/**",
            "provider://afs/image/**",
            "release://afs/**",
        ],
        "forbidden_scope": ["server://production/**"],
        "required_runtime_surfaces": surfaces if surfaces is not None else [SURFACE],
        "provider_budget_minor_units": budget,
        "provider_call_limit": calls,
        "budget_currency": "USD",
        "evaluator_required": evaluator,
        "required_decision_gates": gates or ["provider", "merge"],
    }


def project_packet(project_id: str = "afs") -> dict[str, object]:
    return {
        "schema_version": "companyos.project-spec.v1",
        "project_id": project_id,
        "version": 1,
        "target_outcome": "commercially useful AFS",
        "authority": authority(),
    }


def program_packet(
    project: ProjectSpec, program_id: str = "afs-core"
) -> dict[str, object]:
    return {
        "schema_version": "companyos.program-spec.v1",
        "program_id": program_id,
        "version": 1,
        "project_ref": project.reference().to_dict(),
        "objective": "close the core production loop",
        "state": "compiled",
        "dependency_refs": [],
        "wave": 0,
        "authority": authority(
            read_scope=["repo://afs/src/**"],
            write_scope=[
                "repo://afs/worktrees/core/**",
                "provider://afs/image/**",
                "release://afs/core/**",
            ],
            budget=5_000,
            calls=5,
            gates=["provider", "merge", "release"],
        ),
    }


def goal_packet() -> dict[str, object]:
    return {
        "goal_id": "goal-core",
        "target_outcome": "verified generation path",
        "success_evidence_states": ["runtime_verification"],
        "read_scope": ["repo://afs/src/api/**"],
        "write_scope": [
            "repo://afs/worktrees/core/api/**",
            "provider://afs/image/keyframes/**",
            "release://afs/core/**",
        ],
        "forbidden_scope": ["server://production/**"],
        "allowed_capabilities": [
            "read_local",
            "write_local",
            "provider_cost",
            "repo_remote",
            "public_release",
        ],
        "required_runtime_surfaces": [SURFACE],
        "evaluator_required": True,
        "provider_budget_minor_units": 1_000,
        "provider_call_limit": 2,
        "budget_currency": "USD",
    }


def task_packet(goal_id: str = "goal-core") -> dict[str, object]:
    return {
        "task_id": "task-core",
        "goal_id": goal_id,
        "objective": "implement one bounded path",
        "expected_delta": "runtime",
        "primary_surface": "repo://afs/worktrees/core/api/path.py",
        "evidence_target": "runtime_verification",
        "capabilities": [
            "read_local",
            "write_local",
            "provider_cost",
            "repo_remote",
            "public_release",
        ],
        "read_scope": ["repo://afs/src/api/path.py"],
        "write_scope": [
            "repo://afs/worktrees/core/api/path.py",
            "provider://afs/image/keyframes/model",
            "release://afs/core/v1",
        ],
        "forbidden_scope": ["server://production/**"],
        "required_runtime_surfaces": [SURFACE],
        "evaluator_required": True,
        "integration_required": True,
        "workflow_steps": [],
        "max_attempts": 2,
    }


def forged_gate_authority(authority: CompiledTaskAuthority) -> dict[str, Any]:
    forged = copy.deepcopy(authority.to_dict())
    contract = forged["decision_gate_contracts"][0]
    contract["action"] = "forged-generate"
    contract["request_digest"] = content_hash(
        {
            "gate_id": contract["gate_id"],
            "capability": contract["capability"],
            "action": contract["action"],
            "resource": contract["resource"],
        }
    )
    return forged


class AuthoritySpineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project = compile_project(project_packet())
        self.program = compile_program(
            program_packet(self.project), project=self.project
        )
        self.goal, _ = compile_goal_authority(
            goal_packet(), project=self.project, program=self.program
        )

    def test_valid_chain_is_versioned_digest_bound_and_immutable(self) -> None:
        task, _ = compile_task_authority(
            task_packet(),
            project=self.project,
            program=self.program,
            goal=self.goal,
            provider_budget_minor_units=500,
            provider_call_limit=1,
        )
        self.assertEqual(task.project_ref, self.project.reference())
        self.assertEqual(task.program_ref, self.program.reference())
        self.assertEqual(task.goal_ref, self.goal.reference())
        with self.assertRaises((AttributeError, TypeError)):
            self.program.wave = 2  # type: ignore[misc]

    def test_decision_gate_digest_binds_exact_workflow_request(self) -> None:
        packet = task_packet()
        packet["workflow_steps"] = [
            {
                "step_id": "generate-keyframe",
                "adapter": "image-provider",
                "action": "generate",
                "resource": "provider://afs/image/keyframes/model",
                "request_digest": content_hash(
                    {"prompt": "bounded keyframe", "seed": 7}
                ),
            },
            {
                "step_id": "merge-authority",
                "adapter": "git",
                "action": "merge",
                "resource": "repo://afs/worktrees/core/api/path.py",
                "request_digest": content_hash(
                    {"head": "commit:authority", "base": "commit:runtime"}
                ),
            },
            {
                "step_id": "release-authority",
                "adapter": "release",
                "action": "release",
                "resource": "release://afs/core/v1",
                "request_digest": content_hash(
                    {"artifact": "authority-spine", "version": "v1"}
                ),
            },
        ]
        task, _ = compile_task_authority(
            packet,
            project=self.project,
            program=self.program,
            goal=self.goal,
            provider_budget_minor_units=500,
            provider_call_limit=1,
        )
        workflow_digests = {
            (step["action"], step["resource"]): step["request_digest"]
            for step in task.task_spec.workflow_steps
        }
        for contract in task.decision_gate_contracts:
            self.assertEqual(
                contract.request_digest,
                workflow_digests[(contract.action, contract.resource)],
            )

    def test_from_dict_rejects_forged_gate_action_with_recomputed_digest(self) -> None:
        task, _ = compile_task_authority(
            task_packet(),
            project=self.project,
            program=self.program,
            goal=self.goal,
            provider_budget_minor_units=500,
            provider_call_limit=1,
        )
        with self.assertRaisesRegex(ContractError, "canonical Task gate authority"):
            CompiledTaskAuthority.from_dict(forged_gate_authority(task))

    def test_strict_contracts_reject_unknown_fields(self) -> None:
        packet = project_packet()
        packet["ambient_authority"] = True
        with self.assertRaisesRegex(ContractError, "unsupported fields"):
            compile_project(packet)
        program = program_packet(self.project)
        program["auto_merge"] = True
        with self.assertRaisesRegex(ContractError, "unsupported fields"):
            compile_program(program, project=self.project)

    def test_program_cannot_widen_any_authority_dimension(self) -> None:
        cases = (
            (
                "capabilities",
                authority(capabilities=["read_local", "server_write"]),
                "capabilities",
            ),
            ("read", authority(read_scope=["repo://another/**"]), "read_scope"),
            ("write", authority(write_scope=["repo://afs/release/**"]), "write_scope"),
            ("budget", authority(budget=10_001), "budget"),
            ("calls", authority(calls=11), "call limit"),
            (
                "surface",
                authority(
                    surfaces=[SURFACE, {**SURFACE, "surface_key": "server:prod"}]
                ),
                "runtime surfaces",
            ),
            ("evaluator", authority(evaluator=False), "evaluator"),
            ("decision", authority(gates=["provider"]), "decision gates"),
        )
        for name, child_authority, message in cases:
            with self.subTest(name=name):
                packet = program_packet(self.project)
                packet["authority"] = child_authority
                with self.assertRaisesRegex(ContractError, message):
                    compile_program(packet, project=self.project)

    def test_cross_project_and_stale_refs_are_rejected(self) -> None:
        other = compile_project(project_packet("other"))
        packet = program_packet(self.project)
        packet["project_ref"] = other.reference().to_dict()
        with self.assertRaisesRegex(ContractError, "exact ProjectSpec"):
            compile_program(packet, project=self.project)
        packet = program_packet(self.project)
        stale = dict(self.project.reference().to_dict())
        stale["version"] = 2
        packet["project_ref"] = stale
        with self.assertRaisesRegex(ContractError, "exact ProjectSpec"):
            compile_program(packet, project=self.project)

    def test_program_graph_rejects_cycle_and_invalid_wave(self) -> None:
        first = ProgramSpec.from_dict(program_packet(self.project, "first"))
        second_data = program_packet(self.project, "second")
        second_data["wave"] = 1
        second_data["dependency_refs"] = [first.reference().to_dict()]
        second = ProgramSpec.from_dict(second_data)
        first_data = first.to_dict()
        first_data["dependency_refs"] = [second.reference().to_dict()]
        first_cyclic = ProgramSpec.from_dict(first_data)
        with self.assertRaisesRegex(ContractError, "cycle"):
            validate_program_graph(self.project, [first_cyclic, second])
        same_wave = second.to_dict()
        same_wave["wave"] = 0
        with self.assertRaisesRegex(ContractError, "earlier wave"):
            validate_program_graph(
                self.project, [first, ProgramSpec.from_dict(same_wave)]
            )

    def test_dependency_program_requires_graph_proof_in_compile_path(self) -> None:
        first = compile_program(
            program_packet(self.project, "first"), project=self.project
        )
        second_data = program_packet(self.project, "second")
        second_data["wave"] = 1
        second_data["dependency_refs"] = [first.reference().to_dict()]
        second = ProgramSpec.from_dict(second_data)
        with self.assertRaisesRegex(ContractError, "complete graph proof"):
            compile_program(second_data, project=self.project)
        compiled = compile_program(
            second_data,
            project=self.project,
            program_graph=[first, second],
        )
        self.assertEqual(compiled.reference(), second.reference())

    def test_noncompiled_program_requires_current_state_provider(self) -> None:
        active = program_packet(self.project)
        active["state"] = "active"
        with self.assertRaisesRegex(ContractError, "current-state provider"):
            compile_program(active, project=self.project)

    def test_goal_cannot_bypass_program_or_widen_program(self) -> None:
        other_project = compile_project(project_packet("other"))
        other_program = compile_program(
            program_packet(other_project), project=other_project
        )
        with self.assertRaisesRegex(ContractError, "project_ref|bypass Program"):
            compile_goal_authority(
                goal_packet(), project=self.project, program=other_program
            )
        widened = goal_packet()
        widened["write_scope"] = ["repo://afs/worktrees/other/**"]
        with self.assertRaisesRegex(ContractError, "write_scope"):
            compile_goal_authority(widened, project=self.project, program=self.program)

    def test_forged_program_wrapper_is_revalidated_before_goal_compile(self) -> None:
        forged_data = self.program.to_dict()
        forged_authority = dict(forged_data["authority"])
        forged_authority["capabilities"] = [
            "read_local",
            "write_local",
            "provider_cost",
            "server_write",
        ]
        forged_authority["write_scope"] = ["server://production/runtime/**"]
        forged_authority["forbidden_scope"] = []
        forged_data["authority"] = forged_authority
        forged = ProgramSpec.from_dict(forged_data)
        self.assertEqual(forged.project_ref, self.project.reference())
        with self.assertRaisesRegex(ContractError, "exceed|write_scope"):
            compile_goal_authority(goal_packet(), project=self.project, program=forged)

    def test_task_cannot_bypass_goal_or_widen_budget(self) -> None:
        with self.assertRaisesRegex(ContractError, "goal_id"):
            compile_task_authority(
                task_packet("goal-other"),
                project=self.project,
                program=self.program,
                goal=self.goal,
            )
        with self.assertRaisesRegex(ContractError, "provider budget"):
            compile_task_authority(
                task_packet(),
                project=self.project,
                program=self.program,
                goal=self.goal,
                provider_budget_minor_units=1_001,
                provider_call_limit=1,
            )

    def test_forged_goal_wrapper_is_revalidated_before_task_compile(self) -> None:
        forged_data = self.goal.to_dict()
        forged_goal = dict(forged_data["goal_spec"])
        forged_goal["allowed_capabilities"] = [
            "read_local",
            "write_local",
            "provider_cost",
            "server_write",
        ]
        forged_goal["write_scope"] = ["server://production/runtime/**"]
        forged_goal["forbidden_scope"] = []
        forged_data["goal_spec"] = forged_goal
        forged = CompiledGoalAuthority.from_dict(forged_data)
        self.assertEqual(forged.project_ref, self.project.reference())
        self.assertEqual(forged.program_ref, self.program.reference())
        with self.assertRaisesRegex(ContractError, "exceed|write_scope"):
            compile_task_authority(
                task_packet(),
                project=self.project,
                program=self.program,
                goal=forged,
            )

    def test_terminal_program_cannot_accept_goal_or_task(self) -> None:
        terminal_data = self.program.to_dict()
        terminal_data["state"] = ProgramState.DELIVERED.value
        terminal = ProgramSpec.from_dict(terminal_data)
        with self.assertRaisesRegex(ContractError, "current-state provider"):
            compile_goal_authority(
                goal_packet(), project=self.project, program=terminal
            )
        with self.assertRaisesRegex(ContractError, "current-state provider"):
            compile_task_authority(
                task_packet(), project=self.project, program=terminal, goal=self.goal
            )

    def test_required_runtime_surfaces_cannot_be_dropped(self) -> None:
        packet = program_packet(self.project)
        raw_authority = packet["authority"]
        assert isinstance(raw_authority, dict)
        child = dict(raw_authority)
        child["required_runtime_surfaces"] = []
        packet["authority"] = child
        with self.assertRaisesRegex(ContractError, "drop required runtime surfaces"):
            compile_program(packet, project=self.project)

        goal = goal_packet()
        goal["required_runtime_surfaces"] = []
        with self.assertRaisesRegex(ContractError, "drop required runtime surfaces"):
            compile_goal_authority(goal, project=self.project, program=self.program)

        task = task_packet()
        task["required_runtime_surfaces"] = []
        with self.assertRaisesRegex(ContractError, "drop required runtime surfaces"):
            compile_task_authority(
                task,
                project=self.project,
                program=self.program,
                goal=self.goal,
                provider_budget_minor_units=1,
                provider_call_limit=1,
            )

    def test_decision_gates_are_bound_into_goal_and_task_authority(self) -> None:
        task, _ = compile_task_authority(
            task_packet(),
            project=self.project,
            program=self.program,
            goal=self.goal,
            provider_budget_minor_units=500,
            provider_call_limit=1,
        )
        self.assertEqual(
            self.goal.required_decision_gates,
            self.program.authority.required_decision_gates,
        )
        self.assertEqual(
            task.required_decision_gates, self.goal.required_decision_gates
        )
        forged_data = self.goal.to_dict()
        forged_data["required_decision_gates"] = ["provider"]
        forged = CompiledGoalAuthority.from_dict(forged_data)
        with self.assertRaisesRegex(ContractError, "decision gates"):
            compile_task_authority(
                task_packet(),
                project=self.project,
                program=self.program,
                goal=forged,
            )

    def test_task_compile_rejects_unsatisfiable_decision_gates(self) -> None:
        missing_release = task_packet()
        missing_release["capabilities"] = [
            "read_local",
            "write_local",
            "provider_cost",
            "repo_remote",
        ]
        with self.assertRaisesRegex(ContractError, "release requires capability"):
            compile_task_authority(
                missing_release,
                project=self.project,
                program=self.program,
                goal=self.goal,
                provider_budget_minor_units=500,
                provider_call_limit=1,
            )
        with self.assertRaisesRegex(ContractError, "positive Task budget"):
            compile_task_authority(
                task_packet(),
                project=self.project,
                program=self.program,
                goal=self.goal,
                provider_budget_minor_units=0,
                provider_call_limit=0,
            )
        for label, write_scope, message in (
            ("empty", [], "provider.*provider://"),
            (
                "provider",
                ["repo://afs/worktrees/core/api/path.py", "release://afs/core/v1"],
                "provider.*provider://",
            ),
            (
                "merge",
                ["provider://afs/image/keyframes/model", "release://afs/core/v1"],
                "merge.*repo://",
            ),
            (
                "release",
                [
                    "provider://afs/image/keyframes/model",
                    "repo://afs/worktrees/core/api/path.py",
                ],
                "release.*release://",
            ),
        ):
            with self.subTest(label=label):
                incompatible = task_packet()
                incompatible["write_scope"] = write_scope
                with self.assertRaisesRegex(ContractError, message):
                    compile_task_authority(
                        incompatible,
                        project=self.project,
                        program=self.program,
                        goal=self.goal,
                        provider_budget_minor_units=500,
                        provider_call_limit=1,
                    )


class AuthoritySpineSchemaTests(unittest.TestCase):
    schema: dict[str, Any]
    runtime_schema: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(
            (ROOT / "runtime/contracts/v1/authority-spine.schema.json").read_text(
                encoding="utf-8"
            )
        )
        cls.runtime_schema = json.loads(
            (ROOT / "runtime/contracts/v1/runtime-contracts.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(cls.schema)

    def _validator(self, definition: str) -> Draft202012Validator:
        resolver = RefResolver.from_schema(
            self.schema,
            store={
                "https://companyos.dev/contracts/v1/runtime-contracts.schema.json": self.runtime_schema,
                "runtime-contracts.schema.json": self.runtime_schema,
            },
        )
        return Draft202012Validator(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$ref": f"#/$defs/{definition}",
                "$defs": self.schema["$defs"],
            },
            resolver=resolver,
        )

    def test_schema_accepts_compiler_outputs_and_rejects_unknowns(self) -> None:
        project = compile_project(project_packet())
        program = compile_program(program_packet(project), project=project)
        goal, _ = compile_goal_authority(
            goal_packet(), project=project, program=program
        )
        task, _ = compile_task_authority(
            task_packet(),
            project=project,
            program=program,
            goal=goal,
            provider_budget_minor_units=500,
            provider_call_limit=1,
        )
        for definition, value in (
            ("ProjectSpec", project.to_dict()),
            ("ProgramSpec", program.to_dict()),
            ("CompiledGoalAuthority", goal.to_dict()),
            ("CompiledTaskAuthority", task.to_dict()),
        ):
            with self.subTest(definition=definition):
                self._validator(definition).validate(value)
        invalid = project.to_dict()
        invalid["unknown"] = True
        self.assertTrue(list(self._validator("ProjectSpec").iter_errors(invalid)))


class RuntimeAuthoritySpineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        self.project = compile_project(project_packet())
        self.program = compile_program(
            program_packet(self.project), project=self.project
        )
        self.kernel = RuntimeKernel(
            self.store,
            authority_spines={"afs": (self.project, self.program)},
        )
        self.kernel.initialize()
        self.identities = IdentityFixture(self.store)
        self.goal, _ = compile_goal_authority(
            goal_packet(), project=self.project, program=self.program
        )
        self.task, _ = compile_task_authority(
            task_packet(),
            project=self.project,
            program=self.program,
            goal=self.goal,
            provider_budget_minor_units=500,
            provider_call_limit=1,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _create_bound_running_task(self) -> str:
        self.kernel.create_goal(
            project_id="afs",
            spec=self.goal.goal_spec,
            compiled_authority=self.goal,
            actor=self.identities.owner,
            idempotency_key="bound-goal",
        )
        run_id = "run-authority"
        self.kernel.create_run(
            project_id="afs",
            goal_id=self.goal.goal_spec.goal_id,
            run_id=run_id,
            actor=self.identities.owner,
            idempotency_key="bound-run",
        )
        self.kernel.add_task(
            project_id="afs",
            spec=self.task.task_spec,
            compiled_authority=self.task,
            actor=self.identities.system,
            idempotency_key="bound-task",
            run_id=run_id,
        )
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE runs SET loop_state = 'running' WHERE run_id = ?", (run_id,)
            )
            connection.execute(
                "UPDATE tasks SET state = 'running' WHERE task_id = ?",
                (self.task.task_spec.task_id,),
            )
        return run_id

    def test_plain_goal_and_task_cannot_bypass_enabled_spine(self) -> None:
        with self.assertRaisesRegex(ContractError, "CompiledGoalAuthority"):
            self.kernel.create_goal(
                project_id="afs",
                spec=self.goal.goal_spec,
                actor=self.identities.owner,
                idempotency_key="plain-goal",
            )
        self.kernel.create_goal(
            project_id="afs",
            spec=self.goal.goal_spec,
            compiled_authority=self.goal,
            actor=self.identities.owner,
            idempotency_key="compiled-goal",
        )
        with self.assertRaisesRegex(ContractError, "CompiledTaskAuthority"):
            self.kernel.add_task(
                project_id="afs",
                spec=self.task.task_spec,
                actor=self.identities.system,
                idempotency_key="plain-task",
            )
        created = self.kernel.add_task(
            project_id="afs",
            spec=self.task.task_spec,
            compiled_authority=self.task,
            actor=self.identities.system,
            idempotency_key="compiled-task",
        )
        self.assertEqual(created["task_id"], "task-core")

    def test_restart_restores_durable_goal_and_task_authority_binding(self) -> None:
        self.kernel.create_goal(
            project_id="afs",
            spec=self.goal.goal_spec,
            compiled_authority=self.goal,
            actor=self.identities.owner,
            idempotency_key="compiled-goal-restart",
        )
        restarted = RuntimeKernel(
            self.store,
            authority_spines={"afs": (self.project, self.program)},
        )
        restarted.initialize()
        created = restarted.add_task(
            project_id="afs",
            spec=self.task.task_spec,
            compiled_authority=self.task,
            actor=self.identities.system,
            idempotency_key="task-after-restart",
        )
        self.assertEqual(created["task_id"], "task-core")
        with self.store.transaction() as connection:
            self.assertIsNotNone(
                connection.execute(
                    "SELECT 1 FROM task_authority_bindings WHERE task_id = 'task-core'"
                ).fetchone()
            )

    def test_constructor_omission_cannot_downgrade_adopted_project(self) -> None:
        omitted = RuntimeKernel(self.store)
        another_goal = goal_packet()
        another_goal["goal_id"] = "goal-omission"
        compiled, _ = compile_goal_authority(
            another_goal, project=self.project, program=self.program
        )
        with self.assertRaisesRegex(ContractError, "CompiledGoalAuthority"):
            omitted.create_goal(
                project_id="afs",
                spec=compiled.goal_spec,
                actor=self.identities.owner,
                idempotency_key="omitted-spine",
            )

    def test_persisted_registry_version_and_graph_tamper_fail_closed(self) -> None:
        for column, value in (("version", 999), ("graph_digest", "0" * 64)):
            with self.subTest(column=column):
                with self.store.transaction(immediate=True) as connection:
                    original = connection.execute(
                        f"SELECT {column} FROM adopted_programs WHERE program_id = ?",
                        (self.program.program_id,),
                    ).fetchone()[column]
                    connection.execute(
                        f"UPDATE adopted_programs SET {column} = ? WHERE program_id = ?",
                        (value, self.program.program_id),
                    )
                with self.assertRaisesRegex(ContractError, "digest/state mismatch"):
                    RuntimeKernel(self.store)._persisted_authority_spine("afs")
                with self.store.transaction(immediate=True) as connection:
                    connection.execute(
                        f"UPDATE adopted_programs SET {column} = ? WHERE program_id = ?",
                        (original, self.program.program_id),
                    )

    def test_authority_registry_and_bindings_replay_from_events(self) -> None:
        self.kernel.create_goal(
            project_id="afs",
            spec=self.goal.goal_spec,
            compiled_authority=self.goal,
            actor=self.identities.owner,
            idempotency_key="goal-for-authority-replay",
        )
        self.kernel.add_task(
            project_id="afs",
            spec=self.task.task_spec,
            compiled_authority=self.task,
            actor=self.identities.system,
            idempotency_key="task-for-authority-replay",
        )
        replayed = ProjectionReplayer(self.store).verify()
        self.assertEqual(set(replayed.projects), {"afs"})
        self.assertEqual(set(replayed.programs), {"afs-core"})
        self.assertEqual(set(replayed.goal_authorities), {"goal-core"})
        self.assertEqual(set(replayed.task_authorities), {"task-core"})

        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE task_authority_bindings SET authority_digest = ? WHERE task_id = ?",
                ("0" * 64, "task-core"),
            )
        with self.assertRaisesRegex(IntegrityError, "projection mismatch"):
            ProjectionReplayer(self.store).verify()

    def test_replay_rejects_forged_gate_action_with_recomputed_digest(self) -> None:
        self._create_bound_running_task()
        replayed = ProjectionReplayer(self.store).replay()
        with self.assertRaisesRegex(IntegrityError, "not canonical"):
            ProjectionReplayer._apply_task_authority(
                {},
                replayed.goal_authorities,
                replayed.projects,
                replayed.programs,
                {
                    "aggregate_id": self.task.task_spec.task_id,
                    "event_type": "task_authority_bound",
                    "event_id": "forged-task-authority-event",
                },
                forged_gate_authority(self.task),
            )

    def test_restart_policy_rejects_forged_gate_and_projection_not_bound_to_event(
        self,
    ) -> None:
        run_id = self._create_bound_running_task()
        forged = forged_gate_authority(self.task)
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE task_authority_bindings SET authority_json = ?, "
                "authority_digest = ?, required_decision_gates_json = ? "
                "WHERE task_id = ?",
                (
                    canonical_json(forged),
                    content_hash(forged),
                    canonical_json(forged["decision_gate_contracts"]),
                    self.task.task_spec.task_id,
                ),
            )
        restarted_store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        with restarted_store.transaction() as connection:
            self.assertFalse(
                _required_decision_gates_satisfied(
                    connection, self.task.task_spec.task_id
                )
            )
        with self.assertRaisesRegex(AuthorizationError, "binding is malformed"):
            PolicyEngine(restarted_store).record_approval(
                project_id="afs",
                goal_id=self.goal.goal_spec.goal_id,
                run_id=run_id,
                task_id=self.task.task_spec.task_id,
                requester=self.identities.worker,
                approver=self.identities.owner,
                capability=Capability.PROVIDER_COST,
                action="generate",
                resource="provider://afs/image/keyframes/model",
                request_digest=forged["decision_gate_contracts"][0]["request_digest"],
                policy_version="companyos-policy-v1",
                decision="approved",
                ttl_seconds=600,
            )

    def test_restart_policy_readback_is_bound_to_original_authority_event(self) -> None:
        run_id = self._create_bound_running_task()
        forged = copy.deepcopy(self.task.to_dict())
        forged["task_spec"]["objective"] = "forged but structurally canonical task"
        CompiledTaskAuthority.from_dict(forged)
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE task_authority_bindings SET authority_json = ?, "
                "authority_digest = ? WHERE task_id = ?",
                (
                    canonical_json(forged),
                    content_hash(forged),
                    self.task.task_spec.task_id,
                ),
            )
        restarted_store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        with self.assertRaisesRegex(AuthorizationError, "source event mismatch"):
            PolicyEngine(restarted_store).record_approval(
                project_id="afs",
                goal_id=self.goal.goal_spec.goal_id,
                run_id=run_id,
                task_id=self.task.task_spec.task_id,
                requester=self.identities.worker,
                approver=self.identities.owner,
                capability=Capability.PROVIDER_COST,
                action="generate",
                resource="provider://afs/image/keyframes/model",
                request_digest=self.task.decision_gate_contracts[0].request_digest,
                policy_version="companyos-policy-v1",
                decision="approved",
                ttl_seconds=600,
            )

    def test_runtime_persists_and_revalidates_complete_dependency_graph(self) -> None:
        dependent_data = program_packet(self.project, "afs-release")
        dependent_data["wave"] = 1
        dependent_data["dependency_refs"] = [self.program.reference().to_dict()]
        dependent = ProgramSpec.from_dict(dependent_data)
        graph = (self.program, dependent)
        store = SQLiteStore(Path(self.temp.name) / "graph-runtime.db")
        kernel = RuntimeKernel(
            store,
            authority_spines={"afs": (self.project, dependent, graph)},
        )
        kernel.initialize()
        persisted = RuntimeKernel(store)._persisted_authority_spine("afs")
        self.assertIsNotNone(persisted)
        assert persisted is not None
        self.assertEqual(persisted[1].reference(), dependent.reference())
        self.assertEqual(
            {item.reference() for item in persisted[2]},
            {item.reference() for item in graph},
        )

    def test_replay_rejects_stale_parent_refs_and_forged_complete_graph(self) -> None:
        self._create_bound_running_task()
        replayed = ProjectionReplayer(self.store).replay()

        stale_goal = self.goal.to_dict()
        stale_goal["program_ref"] = {**stale_goal["program_ref"], "version": 999}
        with self.assertRaisesRegex(IntegrityError, "stale parent"):
            ProjectionReplayer._apply_goal_authority(
                {},
                replayed.projects,
                replayed.programs,
                {
                    "aggregate_id": self.goal.goal_spec.goal_id,
                    "event_type": "goal_authority_bound",
                    "event_id": "stale-goal-event",
                },
                stale_goal,
            )

        stale_task = self.task.to_dict()
        stale_task["goal_ref"] = {**stale_task["goal_ref"], "digest": "0" * 64}
        with self.assertRaisesRegex(IntegrityError, "stale parent"):
            ProjectionReplayer._apply_task_authority(
                {},
                replayed.goal_authorities,
                replayed.projects,
                replayed.programs,
                {
                    "aggregate_id": self.task.task_spec.task_id,
                    "event_type": "task_authority_bound",
                    "event_id": "stale-task-event",
                },
                stale_task,
            )

        forged_projects = copy.deepcopy(replayed.projects)
        forged_programs = copy.deepcopy(replayed.programs)
        extra_ref = {
            "kind": "program",
            "object_id": "nonexistent-program",
            "version": 1,
            "digest": "1" * 64,
        }
        for program in forged_programs.values():
            program["_graph_refs"].append(extra_ref)
            program["graph_digest"] = content_hash(program["_graph_refs"])
        with self.assertRaisesRegex(IntegrityError, "incomplete or stale"):
            ProjectionReplayer._validate_authority_graph(
                forged_projects, forged_programs
            )
        malformed_projects = copy.deepcopy(replayed.projects)
        malformed_programs = copy.deepcopy(replayed.programs)
        for program in malformed_programs.values():
            program["_graph_refs"][0]["version"] = "not-an-integer"
            program["graph_digest"] = content_hash(program["_graph_refs"])
        with self.assertRaisesRegex(IntegrityError, "malformed"):
            ProjectionReplayer._validate_authority_graph(
                malformed_projects, malformed_programs
            )

    def test_decision_approvals_succeed_end_to_end_and_missing_binding_fails(
        self,
    ) -> None:
        run_id = self._create_bound_running_task()
        policy = PolicyEngine(self.store)
        gate_contracts = {
            item.gate_id: item for item in self.task.decision_gate_contracts
        }
        provider_contract = gate_contracts["provider"]
        with self.assertRaisesRegex(AuthorizationError, "requires a provider://"):
            policy.record_approval(
                project_id="afs",
                goal_id=self.goal.goal_spec.goal_id,
                run_id=run_id,
                task_id=self.task.task_spec.task_id,
                requester=self.identities.worker,
                approver=self.identities.owner,
                capability=Capability.PROVIDER_COST,
                action="generate",
                resource="repo://afs/worktrees/core/api/path.py",
                request_digest=content_hash({"decision": "wrong-provider-scheme"}),
                policy_version="companyos-policy-v1",
                decision="approved",
                ttl_seconds=600,
            )
        for label, action, digest in (
            ("wrong-action", "invoke", provider_contract.request_digest),
            ("wrong-request", provider_contract.action, content_hash("wrong-request")),
        ):
            policy.record_approval(
                project_id="afs",
                goal_id=self.goal.goal_spec.goal_id,
                run_id=run_id,
                task_id=self.task.task_spec.task_id,
                requester=self.identities.worker,
                approver=self.identities.owner,
                capability=provider_contract.capability,
                action=action,
                resource=provider_contract.resource,
                request_digest=digest,
                policy_version="companyos-policy-v1",
                decision="approved",
                ttl_seconds=600,
                approval_id=f"approval-{label}",
            )
            with self.store.transaction() as connection:
                self.assertFalse(
                    _required_decision_gates_satisfied(
                        connection,
                        self.task.task_spec.task_id,
                        required_gates=("provider",),
                    )
                )
        recorded = []
        for contract in self.task.decision_gate_contracts:
            recorded.append(
                policy.record_approval(
                    project_id="afs",
                    goal_id=self.goal.goal_spec.goal_id,
                    run_id=run_id,
                    task_id=self.task.task_spec.task_id,
                    requester=self.identities.worker,
                    approver=self.identities.owner,
                    capability=contract.capability,
                    action=contract.action,
                    resource=contract.resource,
                    request_digest=contract.request_digest,
                    policy_version="companyos-policy-v1",
                    decision="approved",
                    ttl_seconds=600,
                )
            )
        with self.store.transaction() as connection:
            self.assertTrue(
                _required_decision_gates_satisfied(
                    connection, self.task.task_spec.task_id
                )
            )
        provider_digest = provider_contract.request_digest
        grant_kwargs = dict(
            approval_id=recorded[0].approval_id,
            issuer=self.identities.owner,
            principal=self.identities.worker,
            capability=Capability.PROVIDER_COST,
            action=provider_contract.action,
            resource=provider_contract.resource,
            request_digest=provider_digest,
            policy_version="companyos-policy-v1",
            ttl_seconds=300,
            max_uses=1,
            cost_limit=100,
        )
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE task_authority_bindings SET provider_budget_minor_units = 999 "
                "WHERE task_id = ?",
                (self.task.task_spec.task_id,),
            )
        with self.assertRaisesRegex(AuthorizationError, "decision gates"):
            policy.issue_grant(**grant_kwargs)
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE task_authority_bindings SET provider_budget_minor_units = ? "
                "WHERE task_id = ?",
                (
                    self.task.provider_budget_minor_units,
                    self.task.task_spec.task_id,
                ),
            )
        grant = policy.issue_grant(**grant_kwargs)
        self.assertEqual(grant.cost_limit, 100)
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE task_authority_bindings SET provider_call_limit = 999 "
                "WHERE task_id = ?",
                (self.task.task_spec.task_id,),
            )
        with self.assertRaisesRegex(AuthorizationError, "decision gates"):
            policy.consume(
                grant.grant_id,
                project_id="afs",
                goal_id=self.goal.goal_spec.goal_id,
                run_id=run_id,
                task_id=self.task.task_spec.task_id,
                principal=self.identities.worker,
                capability=Capability.PROVIDER_COST,
                action=provider_contract.action,
                resource=provider_contract.resource,
                request_digest=provider_digest,
                idempotency_key="tampered-budget-consume",
                cost=10,
                effect_id="effect-tampered-budget",
            )
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE task_authority_bindings SET provider_call_limit = ? "
                "WHERE task_id = ?",
                (self.task.provider_call_limit, self.task.task_spec.task_id),
            )

        evidence = EvidenceRegistry(self.store)
        artifact = evidence.register_artifact(
            task_id=self.task.task_spec.task_id,
            kind="test_report",
            uri="artifact://task-core/authority-gate-report",
            content_digest=content_hash("authority gate report"),
            producer_session=self.identities.worker,
        )
        claim = evidence.record_claim(
            task_id=self.task.task_spec.task_id,
            claim="typed decision gates and authority lineage pass",
            evidence_state=EvidenceState.RUNTIME,
            artifact_refs=(artifact.artifact_id,),
            verifier_session=self.identities.evaluator,
            verifier_version="1",
            environment="local",
            evaluator_verdict=EvaluatorVerdict.PASS,
            non_claims=("not provider smoke", "not human acceptance"),
        )
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE tasks SET state = 'integration_pending' WHERE task_id = ?",
                (self.task.task_spec.task_id,),
            )
        queue = IntegrationQueue(self.store)
        item = queue.create(
            task_id=self.task.task_spec.task_id,
            source_ref="branch://authority-gates",
            target_ref="branch://main",
            owner=self.identities.release,
            integration_id="integration-authority-gates",
        )
        delivered = queue.advance(
            item.integration_id,
            target=IntegrationState.DELIVERED,
            actor=self.identities.release,
            evidence_refs=(claim.evidence_id,),
            reason="typed provider, merge, and release decisions approved",
        )
        self.assertEqual(delivered.state, IntegrationState.DELIVERED)
        integration_event = self.store.query(
            "SELECT event_id FROM events WHERE aggregate_type = 'integration' "
            "AND aggregate_id = ? ORDER BY seq DESC LIMIT 1",
            (item.integration_id,),
        )[0]["event_id"]
        ObservationRegistry(self.store).record(
            project_id="afs",
            run_id=run_id,
            surface_key="repo:afs",
            target_identity="commit:abc123",
            observer=self.identities.observer,
            probe_name="git-head",
            probe_version="1",
            status="healthy",
            value={"commit": "abc123"},
            ttl_seconds=120,
            trigger_event_id=integration_event,
        )
        delivery = self.kernel.confirm_task_delivery(
            task_id=self.task.task_spec.task_id,
            actor=self.identities.release,
            idempotency_key="authority-gates-task-delivery",
        )
        self.assertEqual(delivery["state"], "delivered")

        missing_store = SQLiteStore(Path(self.temp.name) / "missing-binding.db")
        missing_kernel = RuntimeKernel(
            missing_store, authority_spines={"afs": (self.project, self.program)}
        )
        missing_kernel.initialize()
        missing_identities = IdentityFixture(missing_store)
        missing_kernel.create_goal(
            project_id="afs",
            spec=self.goal.goal_spec,
            compiled_authority=self.goal,
            actor=missing_identities.owner,
            idempotency_key="missing-goal",
        )
        missing_kernel.create_run(
            project_id="afs",
            goal_id=self.goal.goal_spec.goal_id,
            run_id=run_id,
            actor=missing_identities.owner,
            idempotency_key="missing-run",
        )
        missing_kernel.add_task(
            project_id="afs",
            spec=self.task.task_spec,
            compiled_authority=self.task,
            actor=missing_identities.system,
            idempotency_key="missing-task",
            run_id=run_id,
        )
        with missing_store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE runs SET loop_state = 'running' WHERE run_id = ?", (run_id,)
            )
            connection.execute(
                "UPDATE tasks SET state = 'running' WHERE task_id = ?",
                (self.task.task_spec.task_id,),
            )
            connection.execute(
                "DELETE FROM task_authority_bindings WHERE task_id = ?",
                (self.task.task_spec.task_id,),
            )
            self.assertFalse(
                _required_decision_gates_satisfied(
                    connection, self.task.task_spec.task_id
                )
            )
        with self.assertRaisesRegex(AuthorizationError, "binding is missing"):
            PolicyEngine(missing_store).record_approval(
                project_id="afs",
                goal_id=self.goal.goal_spec.goal_id,
                run_id=run_id,
                task_id=self.task.task_spec.task_id,
                requester=missing_identities.worker,
                approver=missing_identities.owner,
                capability=Capability.PROVIDER_COST,
                action="generate",
                resource="provider://afs/image/keyframes/model",
                request_digest=provider_digest,
                policy_version="companyos-policy-v1",
                decision="approved",
                ttl_seconds=600,
            )

    def test_task_budget_projection_tamper_fails_closed(self) -> None:
        run_id = self._create_bound_running_task()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE task_authority_bindings SET provider_budget_minor_units = 999 "
                "WHERE task_id = ?",
                (self.task.task_spec.task_id,),
            )
            self.assertFalse(
                _required_decision_gates_satisfied(
                    connection, self.task.task_spec.task_id
                )
            )
        with self.assertRaisesRegex(AuthorizationError, "binding mismatch"):
            PolicyEngine(self.store).record_approval(
                project_id="afs",
                goal_id=self.goal.goal_spec.goal_id,
                run_id=run_id,
                task_id=self.task.task_spec.task_id,
                requester=self.identities.worker,
                approver=self.identities.owner,
                capability=Capability.PROVIDER_COST,
                action="generate",
                resource="provider://afs/image/keyframes/model",
                request_digest=content_hash({"decision": "tampered-budget"}),
                policy_version="companyos-policy-v1",
                decision="approved",
                ttl_seconds=600,
            )


if __name__ == "__main__":
    unittest.main()
