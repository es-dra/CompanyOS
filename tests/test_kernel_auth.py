"""Regression coverage for authenticated RuntimeKernel command actors."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from companyos_runtime.errors import AuthorizationError, ContractError, TransitionError
from companyos_runtime.kernel import RuntimeKernel
from companyos_runtime.leases import LeaseManager
from companyos_runtime.replay import ProjectionReplayer
from companyos_runtime.scheduler import TaskScheduler
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import (
    EvaluatorVerdict,
    EvidenceState,
    GoalSpec,
    LoopEvent,
    LoopState,
    RuntimeSurfaceSpec,
    TaskSpec,
    TaskState,
    utc_now,
)

from tests.identity_fixtures import IdentityFixture


class RuntimeKernelAuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        self.kernel = RuntimeKernel(self.store)
        self.kernel.initialize()
        self.identities = IdentityFixture(self.store)
        self.kernel.create_goal(
            project_id="project-1",
            spec=GoalSpec(
                goal_id="goal-1",
                target_outcome="enforce authenticated runtime commands",
                success_evidence_states=(EvidenceState.RUNTIME,),
            ),
            actor=self.identities.owner,
            idempotency_key="goal-create",
        )
        self.kernel.create_run(
            project_id="project-1",
            goal_id="goal-1",
            run_id="run-1",
            actor=self.identities.system,
            idempotency_key="run-create",
        )
        self.kernel.add_task(
            project_id="project-1",
            run_id="run-1",
            spec=TaskSpec(
                task_id="task-1",
                goal_id="goal-1",
                objective="exercise role-scoped commands",
                expected_delta="security",
                primary_surface="runtime://kernel",
                evidence_target=EvidenceState.RUNTIME,
                integration_required=False,
            ),
            actor=self.identities.system,
            idempotency_key="task-add",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _ready_run(self) -> None:
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.GOAL_COMPILED,
            actor=self.identities.system,
            idempotency_key="run-compiled",
        )
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.RUN_READY,
            actor=self.identities.system,
            idempotency_key="run-ready",
        )

    def test_direct_public_task_transition_escape_hatch_is_absent(self) -> None:
        self.assertFalse(hasattr(self.kernel, "transition_task"))
        self.assertFalse(hasattr(RuntimeKernel, "transition_task"))

    def test_command_identifiers_reject_blank_or_whitespace_aliases(self) -> None:
        with self.assertRaisesRegex(ContractError, "project_id"):
            self.kernel.create_goal(
                project_id=" project-1",
                spec=GoalSpec(
                    goal_id="goal-whitespace",
                    target_outcome="reject outer identifier aliases",
                    success_evidence_states=(EvidenceState.RUNTIME,),
                ),
                actor=self.identities.owner,
                idempotency_key="goal-whitespace",
            )
        with self.assertRaisesRegex(ContractError, "run_id"):
            self.kernel.create_run(
                project_id="project-1",
                goal_id="goal-1",
                run_id="   ",
                actor=self.identities.system,
                idempotency_key="run-whitespace",
            )
        with self.assertRaisesRegex(ContractError, "idempotency_key"):
            self.kernel.advance_loop(
                run_id="run-1",
                event=LoopEvent.GOAL_COMPILED,
                actor=self.identities.system,
                idempotency_key=" run-compiled",
            )
        self.assertEqual(
            self.store.query(
                "SELECT * FROM events WHERE aggregate_id IN ('goal-whitespace', '   ')"
            ),
            [],
        )

    def test_unauthenticated_actor_string_cannot_issue_kernel_commands(self) -> None:
        with self.assertRaisesRegex(AuthorizationError, "authenticated session"):
            self.kernel.create_goal(
                project_id="project-1",
                spec=GoalSpec(
                    goal_id="forged-goal",
                    target_outcome="forge owner authority",
                    success_evidence_states=(EvidenceState.RUNTIME,),
                ),
                actor="owner-forgery",  # type: ignore[arg-type]
                idempotency_key="forged-goal-create",
            )

    def test_worker_cannot_forge_evaluator_or_delivery_authority(self) -> None:
        worker = self.identities.worker
        with self.assertRaisesRegex(TransitionError, "evaluator"):
            self.kernel.accept_task_evidence(
                task_id="task-1",
                actor=worker,
                idempotency_key="forged-evaluation",
                evidence_id="missing-evidence",
            )
        with self.assertRaisesRegex(TransitionError, "release"):
            self.kernel.confirm_task_delivery(
                task_id="task-1",
                actor=worker,
                idempotency_key="forged-delivery",
            )

        events = self.store.query(
            "SELECT event_type FROM events WHERE actor = ? ORDER BY seq",
            (worker.principal_id,),
        )
        self.assertEqual(events, [])

    def test_direct_specs_are_canonicalized_before_persistence(self) -> None:
        goal_result = self.kernel.create_goal(
            project_id="project-1",
            spec=GoalSpec(
                goal_id="  goal-canonical  ",
                target_outcome="  persist only canonical authority  ",
                success_evidence_states=(EvidenceState.RUNTIME,),
                required_runtime_surfaces=(
                    RuntimeSurfaceSpec(
                        surface_key="  service://api  ",
                        target_identity="  unit:api.service  ",
                        allowed_probes=("  healthz  ",),
                    ),
                ),
            ),
            actor=self.identities.owner,
            idempotency_key="goal-canonical",
        )
        self.assertEqual(goal_result["goal_id"], "goal-canonical")
        persisted_goal = self.kernel.get_goal("goal-canonical")["spec"]
        self.assertEqual(
            persisted_goal["target_outcome"], "persist only canonical authority"
        )
        self.assertEqual(
            persisted_goal["required_runtime_surfaces"][0],
            {
                "surface_key": "service://api",
                "target_identity": "unit:api.service",
                "allowed_probes": ["healthz"],
                "max_ttl_seconds": 300,
                "trigger_event_required": True,
            },
        )

        task_result = self.kernel.add_task(
            project_id="project-1",
            spec=TaskSpec(
                task_id="  task-canonical  ",
                goal_id="  goal-canonical  ",
                objective="  execute canonical task  ",
                expected_delta="  security  ",
                primary_surface="  runtime://kernel  ",
                evidence_target=EvidenceState.RUNTIME,
                integration_required=False,
            ),
            actor=self.identities.system,
            idempotency_key="task-canonical",
        )
        self.assertEqual(task_result["task_id"], "task-canonical")
        persisted_task = self.kernel.get_task("task-canonical")["spec"]
        self.assertEqual(persisted_task["goal_id"], "goal-canonical")
        self.assertEqual(persisted_task["objective"], "execute canonical task")

    def test_malformed_direct_specs_are_rejected_before_persistence(self) -> None:
        malformed_surface = RuntimeSurfaceSpec(
            surface_key="service://api",
            target_identity="unit:api.service",
            allowed_probes="healthz",  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(ContractError, "allowed_probes must be a tuple"):
            self.kernel.create_goal(
                project_id="project-1",
                spec=GoalSpec(
                    goal_id="goal-malformed-surface",
                    target_outcome="reject malformed surface",
                    success_evidence_states=(EvidenceState.RUNTIME,),
                    required_runtime_surfaces=(malformed_surface,),
                ),
                actor=self.identities.owner,
                idempotency_key="goal-malformed-surface",
            )

        with self.assertRaisesRegex(
            ContractError, "task_spec.read_scope must be a tuple"
        ):
            self.kernel.add_task(
                project_id="project-1",
                spec=TaskSpec(
                    task_id="task-malformed-scope",
                    goal_id="goal-1",
                    objective="reject list-like authority drift",
                    expected_delta="security",
                    primary_surface="runtime://kernel",
                    evidence_target=EvidenceState.RUNTIME,
                    read_scope="local://repo",  # type: ignore[arg-type]
                    integration_required=False,
                ),
                actor=self.identities.system,
                idempotency_key="task-malformed-scope",
                run_id="run-1",
            )
        self.assertEqual(
            self.store.query(
                "SELECT task_id FROM tasks WHERE task_id = 'task-malformed-scope'"
            ),
            [],
        )

    def test_delivered_run_is_sealed_against_new_tasks(self) -> None:
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE runs SET loop_state = ? WHERE run_id = ?",
                (LoopState.DELIVERED.value, "run-1"),
            )
        with self.assertRaisesRegex(TransitionError, "sealed against new tasks"):
            self.kernel.add_task(
                project_id="project-1",
                run_id="run-1",
                spec=TaskSpec(
                    task_id="task-after-delivery",
                    goal_id="goal-1",
                    objective="mutate a delivered run",
                    expected_delta="forged scope expansion",
                    primary_surface="runtime://kernel",
                    evidence_target=EvidenceState.RUNTIME,
                    integration_required=False,
                ),
                actor=self.identities.system,
                idempotency_key="task-after-delivery",
            )
        self.assertEqual(
            self.store.query(
                "SELECT task_id FROM tasks WHERE task_id = 'task-after-delivery'"
            ),
            [],
        )

    def test_task_started_requires_exact_run_and_authenticated_lease_holder(
        self,
    ) -> None:
        self.kernel.create_run(
            project_id="project-1",
            goal_id="goal-1",
            run_id="run-2",
            actor=self.identities.system,
            idempotency_key="run-2-create",
        )
        self.kernel.add_task(
            project_id="project-1",
            run_id="run-2",
            spec=TaskSpec(
                task_id="task-2",
                goal_id="goal-1",
                objective="hold an unrelated run lease",
                expected_delta="isolation",
                primary_surface="runtime://kernel",
                evidence_target=EvidenceState.RUNTIME,
                integration_required=False,
            ),
            actor=self.identities.system,
            idempotency_key="task-2-add",
        )
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.GOAL_COMPILED,
            actor=self.identities.system,
            idempotency_key="run-1-compiled",
        )
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.RUN_READY,
            actor=self.identities.system,
            idempotency_key="run-1-ready",
        )
        worker_a = self.identities.worker_named("lease-owner-a")
        worker_b = self.identities.worker_named("lease-owner-b")
        leases = LeaseManager(self.store)
        cross_run = leases.acquire(
            resource_key="repo://cross-run",
            project_id="project-1",
            task_id="task-2",
            holder=worker_a,
            ttl_seconds=60,
        )
        with self.assertRaisesRegex(TransitionError, "lease_valid"):
            self.kernel.advance_loop(
                run_id="run-1",
                event=LoopEvent.TASK_STARTED,
                actor=worker_a,
                idempotency_key="cross-run-task-start",
                payload={
                    "task_id": "task-2",
                    "resource_key": "repo://cross-run",
                    "holder": worker_a.principal_id,
                    "fence": cross_run.fence,
                },
            )

        wrong_actor = leases.acquire(
            resource_key="repo://wrong-actor",
            project_id="project-1",
            task_id="task-1",
            holder=worker_a,
            ttl_seconds=60,
        )
        with self.assertRaisesRegex(TransitionError, "lease_valid"):
            self.kernel.advance_loop(
                run_id="run-1",
                event=LoopEvent.TASK_STARTED,
                actor=worker_b,
                idempotency_key="wrong-actor-task-start",
                payload={
                    "task_id": "task-1",
                    "resource_key": "repo://wrong-actor",
                    "holder": worker_a.principal_id,
                    "fence": wrong_actor.fence,
                },
            )
        self.assertEqual(
            self.kernel.get_run("run-1")["loop_state"], LoopState.READY.value
        )

    def test_supplied_evidence_id_must_itself_be_passing(self) -> None:
        self._ready_run()
        scheduler = TaskScheduler(self.store)
        worker = self.identities.worker
        claim = scheduler.claim_next(project_id="project-1", worker=worker)
        self.assertIsNotNone(claim)
        assert claim is not None
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.TASK_STARTED,
            actor=worker,
            idempotency_key="run-task-started",
            payload={
                "task_id": claim.task_id,
                "resource_key": claim.resource_key,
                "holder": worker.principal_id,
                "fence": claim.fence,
            },
        )
        scheduler.start(claim, worker=worker)
        scheduler.complete(claim, worker=worker)
        evaluator = self.identities.evaluator
        now = utc_now()
        claims = (
            (
                "evidence-good",
                EvidenceState.RUNTIME.value,
                EvaluatorVerdict.NOT_REQUIRED.value,
            ),
            ("evidence-fail", EvidenceState.RUNTIME.value, EvaluatorVerdict.FAIL.value),
            (
                "evidence-wrong-state",
                EvidenceState.STRUCTURE.value,
                EvaluatorVerdict.PASS.value,
            ),
        )
        with self.store.transaction(immediate=True) as connection:
            connection.executemany(
                "INSERT INTO evidence_claims(evidence_id, project_id, run_id, task_id, "
                "claim, evidence_state, artifact_refs_json, verifier_principal_id, "
                "verifier_version, environment, evaluator_verdict, non_claims_json, created_at) "
                "VALUES (?, 'project-1', 'run-1', 'task-1', 'focused regression', ?, "
                "'[]', ?, 'test-v1', 'local', ?, '[]', ?)",
                [
                    (evidence_id, state, evaluator.principal_id, verdict, now)
                    for evidence_id, state, verdict in claims
                ],
            )

        for evidence_id in ("evidence-fail", "evidence-wrong-state"):
            with self.subTest(evidence_id=evidence_id):
                with self.assertRaisesRegex(
                    TransitionError, "does not itself pass the task target"
                ):
                    self.kernel.accept_task_evidence(
                        task_id="task-1",
                        actor=evaluator,
                        idempotency_key=f"accept-{evidence_id}",
                        evidence_id=evidence_id,
                    )
        self.assertEqual(
            self.kernel.get_task("task-1")["state"],
            TaskState.EVIDENCE_PENDING.value,
        )
        accepted = self.kernel.accept_task_evidence(
            task_id="task-1",
            actor=evaluator,
            idempotency_key="accept-evidence-good",
            evidence_id="evidence-good",
        )
        self.assertEqual(accepted["state"], TaskState.INTEGRATION_PENDING.value)

    def test_required_evaluator_cannot_borrow_pass_for_supplied_not_required(
        self,
    ) -> None:
        row = self.store.query("SELECT spec_json FROM tasks WHERE task_id = 'task-1'")[
            0
        ]
        spec = json.loads(row["spec_json"])
        spec["evaluator_required"] = True
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE tasks SET spec_json = ? WHERE task_id = 'task-1'",
                (json.dumps(spec, sort_keys=True, separators=(",", ":")),),
            )
        self._ready_run()
        scheduler = TaskScheduler(self.store)
        worker = self.identities.worker
        claim = scheduler.claim_next(project_id="project-1", worker=worker)
        self.assertIsNotNone(claim)
        assert claim is not None
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.TASK_STARTED,
            actor=worker,
            idempotency_key="run-required-evaluator-started",
            payload={
                "task_id": claim.task_id,
                "resource_key": claim.resource_key,
                "holder": worker.principal_id,
                "fence": claim.fence,
            },
        )
        scheduler.start(claim, worker=worker)
        scheduler.complete(claim, worker=worker)
        evaluator = self.identities.evaluator
        now = utc_now()
        with self.store.transaction(immediate=True) as connection:
            connection.executemany(
                "INSERT INTO evidence_claims(evidence_id, project_id, run_id, task_id, "
                "claim, evidence_state, artifact_refs_json, verifier_principal_id, "
                "verifier_version, environment, evaluator_verdict, non_claims_json, created_at) "
                "VALUES (?, 'project-1', 'run-1', 'task-1', 'focused regression', "
                "'runtime_verification', '[]', ?, 'test-v1', 'local', ?, '[]', ?)",
                (
                    (
                        "evidence-referenced-not-required",
                        evaluator.principal_id,
                        EvaluatorVerdict.NOT_REQUIRED.value,
                        now,
                    ),
                    (
                        "evidence-unreferenced-pass",
                        evaluator.principal_id,
                        EvaluatorVerdict.PASS.value,
                        now,
                    ),
                ),
            )
        with self.assertRaisesRegex(
            TransitionError, "does not itself pass the task target"
        ):
            self.kernel.accept_task_evidence(
                task_id="task-1",
                actor=evaluator,
                idempotency_key="reject-borrowed-required-pass",
                evidence_id="evidence-referenced-not-required",
            )
        self.assertEqual(
            self.kernel.get_task("task-1")["state"],
            TaskState.EVIDENCE_PENDING.value,
        )

    def test_delivery_requires_exact_success_for_every_declared_workflow_step(
        self,
    ) -> None:
        row = self.store.query("SELECT spec_json FROM tasks WHERE task_id = 'task-1'")[
            0
        ]
        spec = json.loads(row["spec_json"])
        spec["workflow_steps"] = [
            {
                "step_id": "required-effect",
                "adapter": "local",
                "action": "write",
                "resource": "runtime://kernel",
                "request_digest": "a" * 64,
            }
        ]
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE tasks SET spec_json = ? WHERE task_id = 'task-1'",
                (json.dumps(spec, sort_keys=True, separators=(",", ":")),),
            )
        self._ready_run()
        scheduler = TaskScheduler(self.store)
        worker = self.identities.worker
        claim = scheduler.claim_next(project_id="project-1", worker=worker)
        self.assertIsNotNone(claim)
        assert claim is not None
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.TASK_STARTED,
            actor=worker,
            idempotency_key="run-workflow-closure-started",
            payload={
                "task_id": claim.task_id,
                "resource_key": claim.resource_key,
                "holder": worker.principal_id,
                "fence": claim.fence,
            },
        )
        scheduler.start(claim, worker=worker)
        scheduler.complete(claim, worker=worker)
        now = utc_now()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "INSERT INTO evidence_claims(evidence_id, project_id, run_id, task_id, "
                "claim, evidence_state, artifact_refs_json, verifier_principal_id, "
                "verifier_version, environment, evaluator_verdict, non_claims_json, created_at) "
                "VALUES ('workflow-evidence', 'project-1', 'run-1', 'task-1', "
                "'workflow closure regression', 'runtime_verification', '[]', ?, "
                "'test-v1', 'local', 'not_required', '[]', ?)",
                (self.identities.system.principal_id, now),
            )
        self.kernel.accept_task_evidence(
            task_id="task-1",
            actor=self.identities.system,
            idempotency_key="accept-workflow-evidence",
            evidence_id="workflow-evidence",
        )
        with self.assertRaisesRegex(TransitionError, "workflow steps"):
            self.kernel.confirm_task_delivery(
                task_id="task-1",
                actor=self.identities.release,
                idempotency_key="reject-missing-workflow-step",
            )
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "INSERT INTO workflow_steps(task_id, step_id, status, input_digest, "
                "result_json, effect_id, started_at, completed_at) "
                "VALUES ('task-1', 'required-effect', 'succeeded', ?, '{}', NULL, ?, ?)",
                ("a" * 64, now, now),
            )
        delivered = self.kernel.confirm_task_delivery(
            task_id="task-1",
            actor=self.identities.release,
            idempotency_key="deliver-complete-workflow",
        )
        self.assertEqual(delivered["state"], TaskState.DELIVERED.value)

    def test_owner_system_task_controls_are_explicit_evented_and_state_strict(
        self,
    ) -> None:
        blocked = self.kernel.control_task(
            task_id="task-1",
            action="block",
            reason="owner decision required",
            actor=self.identities.owner,
            idempotency_key="task-1-block",
        )
        self.assertEqual(blocked["state"], TaskState.BLOCKED.value)
        resumed = self.kernel.control_task(
            task_id="task-1",
            action="resume",
            reason="decision recorded",
            actor=self.identities.owner,
            idempotency_key="task-1-resume",
        )
        self.assertEqual(resumed["state"], TaskState.READY.value)
        deleted = self.kernel.control_task(
            task_id="task-1",
            action="delete",
            reason="obsolete before execution",
            actor=self.identities.system,
            idempotency_key="task-1-delete",
        )
        self.assertEqual(deleted["state"], TaskState.DELETED.value)
        with self.assertRaisesRegex(TransitionError, "cannot resume from state"):
            self.kernel.control_task(
                task_id="task-1",
                action="resume",
                reason="illegal terminal restart",
                actor=self.identities.system,
                idempotency_key="task-1-illegal-resume",
            )

        self.kernel.add_task(
            project_id="project-1",
            run_id="run-1",
            spec=TaskSpec(
                task_id="task-cancel",
                goal_id="goal-1",
                objective="exercise cancel and retire controls",
                expected_delta="state coverage",
                primary_surface="runtime://kernel",
                evidence_target=EvidenceState.RUNTIME,
                integration_required=False,
            ),
            actor=self.identities.system,
            idempotency_key="task-cancel-add",
        )
        canceled = self.kernel.control_task(
            task_id="task-cancel",
            action="cancel",
            reason="scope withdrawn",
            actor=self.identities.owner,
            idempotency_key="task-cancel-control",
        )
        self.assertEqual(canceled["state"], TaskState.CANCELED.value)
        retired = self.kernel.control_task(
            task_id="task-cancel",
            action="retire",
            reason="retain terminal audit only",
            actor=self.identities.owner,
            idempotency_key="task-retire-control",
        )
        self.assertEqual(retired["state"], TaskState.RETIRED.value)

        self.kernel.add_task(
            project_id="project-1",
            run_id="run-1",
            spec=TaskSpec(
                task_id="task-suspend",
                goal_id="goal-1",
                objective="exercise suspend and resume controls",
                expected_delta="state coverage",
                primary_surface="runtime://kernel",
                evidence_target=EvidenceState.RUNTIME,
                integration_required=False,
            ),
            actor=self.identities.system,
            idempotency_key="task-suspend-add",
        )
        self._ready_run()
        scheduler = TaskScheduler(self.store)
        worker = self.identities.worker
        claim = scheduler.claim_next(project_id="project-1", worker=worker)
        self.assertIsNotNone(claim)
        assert claim is not None
        self.assertEqual(claim.task_id, "task-suspend")
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.TASK_STARTED,
            actor=worker,
            idempotency_key="run-task-suspend-started",
            payload={
                "task_id": claim.task_id,
                "resource_key": claim.resource_key,
                "holder": worker.principal_id,
                "fence": claim.fence,
            },
        )
        scheduler.start(claim, worker=worker)
        suspended = self.kernel.control_task(
            task_id="task-suspend",
            action="suspend",
            reason="await exact input",
            actor=self.identities.owner,
            idempotency_key="task-suspend-control",
        )
        self.assertEqual(suspended["state"], TaskState.SUSPENDED.value)
        resumed_claim = self.kernel.control_task(
            task_id="task-suspend",
            action="resume",
            reason="required input supplied",
            actor=self.identities.system,
            idempotency_key="task-suspend-resume",
        )
        self.assertEqual(resumed_claim["state"], TaskState.LEASED.value)
        scheduler.start(claim, worker=worker)
        final_block = self.kernel.control_task(
            task_id="task-suspend",
            action="block",
            reason="stop bounded regression run",
            actor=self.identities.system,
            idempotency_key="task-suspend-final-block",
        )
        self.assertEqual(final_block["state"], TaskState.BLOCKED.value)
        lease = self.store.query(
            "SELECT released_at FROM leases WHERE resource_key = ?",
            (claim.resource_key,),
        )[0]
        self.assertIsNotNone(lease["released_at"])

        control_events = self.store.query(
            "SELECT auth_context_json, payload_json FROM events "
            "WHERE aggregate_type = 'task' AND event_type = 'task_state_changed' "
            "AND idempotency_key = ?",
            ("task-suspend-control",),
        )
        self.assertEqual(len(control_events), 1)
        self.assertEqual(
            json.loads(control_events[0]["auth_context_json"])["handler"],
            "runtime_kernel",
        )
        self.assertIn(
            "control:suspend: await exact input",
            json.loads(control_events[0]["payload_json"])["reason"],
        )
        ProjectionReplayer(self.store).verify()


if __name__ == "__main__":
    unittest.main()
