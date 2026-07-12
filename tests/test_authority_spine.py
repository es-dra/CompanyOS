"""Contract and negative-path tests for the Project/Program authority spine."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, RefResolver  # type: ignore[import-untyped]

from companyos_runtime.authority import (
    CompiledGoalAuthority,
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
from companyos_runtime.errors import ContractError, IntegrityError
from companyos_runtime.kernel import RuntimeKernel
from companyos_runtime.replay import ProjectionReplayer
from companyos_runtime.store import SQLiteStore
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
        "capabilities": capabilities or ["read_local", "write_local", "provider_cost"],
        "read_scope": read_scope or ["repo://afs/**"],
        "write_scope": write_scope or ["repo://afs/worktrees/**"],
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


def program_packet(project: ProjectSpec, program_id: str = "afs-core") -> dict[str, object]:
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
            write_scope=["repo://afs/worktrees/core/**"],
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
        "write_scope": ["repo://afs/worktrees/core/api/**"],
        "forbidden_scope": ["server://production/**"],
        "allowed_capabilities": ["read_local", "write_local", "provider_cost"],
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
        "capabilities": ["read_local", "write_local", "provider_cost"],
        "read_scope": ["repo://afs/src/api/path.py"],
        "write_scope": ["repo://afs/worktrees/core/api/path.py"],
        "forbidden_scope": ["server://production/**"],
        "required_runtime_surfaces": [SURFACE],
        "evaluator_required": True,
        "integration_required": True,
        "workflow_steps": [],
        "max_attempts": 2,
    }


class AuthoritySpineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project = compile_project(project_packet())
        self.program = compile_program(program_packet(self.project), project=self.project)
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
            ("capabilities", authority(capabilities=["read_local", "server_write"]), "capabilities"),
            ("read", authority(read_scope=["repo://another/**"]), "read_scope"),
            ("write", authority(write_scope=["repo://afs/release/**"]), "write_scope"),
            ("budget", authority(budget=10_001), "budget"),
            ("calls", authority(calls=11), "call limit"),
            (
                "surface",
                authority(surfaces=[SURFACE, {**SURFACE, "surface_key": "server:prod"}]),
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
            compile_goal_authority(
                widened, project=self.project, program=self.program
            )

    def test_forged_program_wrapper_is_revalidated_before_goal_compile(self) -> None:
        forged_data = self.program.to_dict()
        forged_authority = dict(forged_data["authority"])
        forged_authority["capabilities"] = [
            "read_local", "write_local", "provider_cost", "server_write"
        ]
        forged_authority["write_scope"] = ["server://production/runtime/**"]
        forged_authority["forbidden_scope"] = []
        forged_data["authority"] = forged_authority
        forged = ProgramSpec.from_dict(forged_data)
        self.assertEqual(forged.project_ref, self.project.reference())
        with self.assertRaisesRegex(ContractError, "exceed|write_scope"):
            compile_goal_authority(
                goal_packet(), project=self.project, program=forged
            )

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
            "read_local", "write_local", "provider_cost", "server_write"
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
        self.assertEqual(task.required_decision_gates, self.goal.required_decision_gates)
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
        goal, _ = compile_goal_authority(goal_packet(), project=project, program=program)
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
        self.program = compile_program(program_packet(self.project), project=self.project)
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


if __name__ == "__main__":
    unittest.main()
