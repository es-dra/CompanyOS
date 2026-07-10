from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from companyos_runtime.errors import EvidenceError, TransitionError
from companyos_runtime.evidence import EvidenceRegistry
from companyos_runtime.integration import IntegrationQueue
from companyos_runtime.kernel import RuntimeKernel
from companyos_runtime.leases import LeaseManager
from companyos_runtime.observations import ObservationRegistry
from companyos_runtime.scheduler import TaskScheduler
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import (
    EvidenceState,
    EvaluatorVerdict,
    GoalSpec,
    IntegrationState,
    LoopEvent,
    LoopState,
    RuntimeSurfaceSpec,
    TaskSpec,
    content_hash,
)

from tests.identity_fixtures import IdentityFixture


class IntegrationQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        self.kernel = RuntimeKernel(self.store)
        self.kernel.initialize()
        self.identities = IdentityFixture(self.store)
        self.worker = self.identities.worker
        self.evaluator = self.identities.evaluator
        self.runtime_surface = RuntimeSurfaceSpec(
            surface_key="repo:main",
            target_identity="commit:integrated",
            allowed_probes=("git_head_probe",),
            max_ttl_seconds=120,
            trigger_event_required=True,
        )
        self.kernel.create_goal(
            project_id="project-1",
            spec=GoalSpec(
                goal_id="goal-1",
                target_outcome="route verified work through integration",
                success_evidence_states=(EvidenceState.STRUCTURE,),
                required_runtime_surfaces=(self.runtime_surface,),
            ),
            actor=self.identities.owner,
            idempotency_key="goal-create",
        )
        self.kernel.create_run(
            project_id="project-1",
            goal_id="goal-1",
            run_id="run-1",
            actor=self.identities.owner,
            idempotency_key="run-create",
        )
        self.kernel.add_task(
            project_id="project-1",
            run_id="run-1",
            spec=TaskSpec(
                task_id="task-1",
                goal_id="goal-1",
                objective="complete the integration route",
                expected_delta="integration",
                primary_surface="repo://change",
                evidence_target=EvidenceState.STRUCTURE,
                required_runtime_surfaces=(self.runtime_surface,),
            ),
            actor=self.identities.owner,
            idempotency_key="task-create",
        )
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.GOAL_COMPILED,
            actor=self.identities.system,
            idempotency_key="loop-compile",
        )
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.RUN_READY,
            actor=self.identities.system,
            idempotency_key="loop-ready",
        )
        self.queue = IntegrationQueue(self.store)
        self.observations = ObservationRegistry(self.store)
        self.leases = LeaseManager(self.store)
        self.lease = self.leases.acquire(
            resource_key="repo://change",
            project_id="project-1",
            task_id="task-1",
            holder=self.worker,
            ttl_seconds=600,
        )
        scheduler = TaskScheduler(self.store)
        task_claim = scheduler.claim_next(
            project_id="project-1", worker=self.worker, ttl_seconds=600
        )
        self.assertIsNotNone(task_claim)
        assert task_claim is not None
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.TASK_STARTED,
            actor=self.worker,
            idempotency_key="loop-running",
            payload={
                "task_id": "task-1",
                "resource_key": "repo://change",
                "holder": self.worker.principal_id,
                "fence": self.lease.fence,
            },
        )
        scheduler.start(task_claim, worker=self.worker)
        scheduler.complete(task_claim, worker=self.worker)
        self.evidence = EvidenceRegistry(self.store)
        report = self.evidence.register_artifact(
            task_id="task-1",
            kind="test_report",
            uri="artifact://task-1/structure-report",
            content_digest=content_hash("task-1 structure report"),
            producer_session=self.worker,
        )
        self.claim = self.evidence.record_claim(
            task_id="task-1",
            claim="the integration artifact has a valid structure",
            evidence_state=EvidenceState.STRUCTURE,
            artifact_refs=(report.artifact_id,),
            verifier_session=self.identities.system,
            verifier_version="1",
            environment="local",
            evaluator_verdict=EvaluatorVerdict.NOT_REQUIRED,
            non_claims=("not runtime freshness", "not human acceptance"),
        )
        self.kernel.accept_task_evidence(
            task_id="task-1",
            actor=self.identities.system,
            idempotency_key="task-evidence-accepted",
            evidence_id=self.claim.evidence_id,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _item(self):
        return self.queue.create(
            task_id="task-1",
            source_ref="branch://feature",
            target_ref="branch://main",
            owner=self.identities.release,
            integration_id="integration-1",
        )

    def _advance_run_to_integration_pending(self) -> None:
        transitions: tuple[tuple[LoopEvent, dict[str, Any], str], ...] = (
            (LoopEvent.EVIDENCE_SUBMITTED, {"task_id": "task-1"}, "loop-evidence"),
            (
                LoopEvent.EVALUATOR_VERDICT_RECEIVED,
                {"task_id": "task-1"},
                "loop-integration",
            ),
        )
        actors = {
            LoopEvent.EVIDENCE_SUBMITTED: self.worker,
            LoopEvent.EVALUATOR_VERDICT_RECEIVED: self.evaluator,
        }
        for event, payload, key in transitions:
            self.kernel.advance_loop(
                run_id="run-1",
                event=event,
                actor=actors[event],
                idempotency_key=key,
                payload=payload,
            )
        self.assertEqual(
            self.kernel.get_run("run-1")["loop_state"],
            LoopState.INTEGRATION_PENDING.value,
        )

    def test_illegal_transition_is_rejected_without_mutating_queue_or_events(
        self,
    ) -> None:
        item = self._item()
        event_count = len(
            self.store.query(
                "SELECT event_id FROM events WHERE aggregate_type = 'integration' AND aggregate_id = ?",
                (item.integration_id,),
            )
        )
        with self.assertRaises(TransitionError):
            self.queue.advance(
                item.integration_id,
                target=IntegrationState.RUNTIME_CHECK_PENDING,
                actor=self.identities.release,
                reason="attempt to skip review, push, CI, merge and deploy",
            )
        row = self.store.query(
            "SELECT state FROM integration_items WHERE integration_id = ?",
            (item.integration_id,),
        )[0]
        self.assertEqual(row["state"], IntegrationState.REVIEW_PENDING.value)
        self.assertEqual(
            len(
                self.store.query(
                    "SELECT event_id FROM events WHERE aggregate_type = 'integration' AND aggregate_id = ?",
                    (item.integration_id,),
                )
            ),
            event_count,
        )

    def test_create_cannot_seed_a_terminal_state_and_bypass_transitions(self) -> None:
        with self.assertRaises(TransitionError):
            self.queue.create(
                task_id="task-1",
                source_ref="branch://feature",
                target_ref="branch://main",
                owner=self.identities.release,
                initial_state=IntegrationState.DELIVERED,
                integration_id="terminal-seed",
            )
        self.assertEqual(
            self.store.query(
                "SELECT * FROM integration_items WHERE integration_id = ?",
                ("terminal-seed",),
            ),
            [],
        )

    def test_incomplete_integration_and_false_delivery_guard_block_delivery(
        self,
    ) -> None:
        item = self._item()
        with self.assertRaises(TransitionError):
            self.queue.require_task_satisfied("task-1")
        self._advance_run_to_integration_pending()

        with self.assertRaises(TransitionError):
            self.kernel.advance_loop(
                run_id="run-1",
                event=LoopEvent.DELIVERY_CONFIRMED,
                actor=self.identities.release,
                idempotency_key="delivery-incomplete",
                guard_results={
                    "evidence_satisfied": True,
                    "evaluator_satisfied": True,
                    "integration_satisfied": False,
                    "freshness_satisfied": True,
                },
            )
        self.assertEqual(
            self.kernel.get_run("run-1")["loop_state"],
            LoopState.INTEGRATION_PENDING.value,
        )

        delivered_item = self.queue.advance(
            item.integration_id,
            target=IntegrationState.DELIVERED,
            actor=self.identities.release,
            evidence_refs=(self.claim.evidence_id,),
            reason="bounded local integration route completed",
        )
        self.assertEqual(delivered_item.state, IntegrationState.DELIVERED)
        self.assertEqual(len(self.queue.require_task_satisfied("task-1")), 1)
        integration_event = self.store.query(
            "SELECT event_id FROM events WHERE aggregate_type = 'integration' "
            "AND aggregate_id = ? ORDER BY seq DESC LIMIT 1",
            (item.integration_id,),
        )[0]["event_id"]
        self.observations.record(
            project_id="project-1",
            run_id="run-1",
            surface_key=self.runtime_surface.surface_key,
            target_identity=self.runtime_surface.target_identity,
            observer=self.identities.observer,
            probe_name="git_head_probe",
            probe_version="1",
            status="healthy",
            value={"commit": "integrated"},
            ttl_seconds=120,
            trigger_event_id=integration_event,
        )
        self.kernel.confirm_task_delivery(
            task_id="task-1",
            actor=self.identities.release,
            idempotency_key="task-delivery-complete",
        )
        delivered_run = self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.DELIVERY_CONFIRMED,
            actor=self.identities.release,
            idempotency_key="delivery-complete",
        )
        self.assertEqual(delivered_run["loop_state"], LoopState.DELIVERED.value)
        with self.assertRaisesRegex(TransitionError, "sealed"):
            self.queue.create(
                task_id="task-1",
                source_ref="branch://late-change",
                target_ref="branch://main",
                owner=self.identities.release,
                integration_id="late-integration",
            )

    def test_true_caller_guard_cannot_override_an_incomplete_durable_queue(
        self,
    ) -> None:
        self._item()
        self._advance_run_to_integration_pending()
        with self.assertRaises(TransitionError):
            self.kernel.advance_loop(
                run_id="run-1",
                event=LoopEvent.DELIVERY_CONFIRMED,
                actor=self.identities.release,
                idempotency_key="delivery-false-claim",
                guard_results={
                    "evidence_satisfied": True,
                    "evaluator_satisfied": True,
                    "integration_satisfied": True,
                    "freshness_satisfied": True,
                },
            )
        self.assertEqual(
            self.kernel.get_run("run-1")["loop_state"],
            LoopState.INTEGRATION_PENDING.value,
        )

    def test_final_integration_state_requires_passing_evidence_reference(self) -> None:
        item = self._item()
        with self.assertRaisesRegex(EvidenceError, "requires evidence references"):
            self.queue.advance(
                item.integration_id,
                target=IntegrationState.DELIVERED,
                actor=self.identities.release,
                reason="attempt evidence-free finalization",
            )
        self.assertEqual(
            self.store.query(
                "SELECT state FROM integration_items WHERE integration_id = ?",
                (item.integration_id,),
            )[0]["state"],
            IntegrationState.REVIEW_PENDING.value,
        )

    def test_final_integration_cannot_borrow_an_unreferenced_passing_claim(
        self,
    ) -> None:
        failed = self.evidence.record_claim(
            task_id="task-1",
            claim="the referenced integration evidence failed",
            evidence_state=EvidenceState.STRUCTURE,
            artifact_refs=(self.claim.artifact_refs[0],),
            verifier_session=self.identities.system,
            verifier_version="1",
            environment="local",
            evaluator_verdict=EvaluatorVerdict.FAIL,
            non_claims=("not passing evidence",),
        )
        item = self._item()
        with self.assertRaisesRegex(EvidenceError, "passing task evidence"):
            self.queue.advance(
                item.integration_id,
                target=IntegrationState.DELIVERED,
                actor=self.identities.release,
                evidence_refs=(failed.evidence_id,),
                reason="attempt to borrow a different unreferenced PASS",
            )

    def test_required_evaluator_reference_cannot_borrow_unreferenced_pass(
        self,
    ) -> None:
        task = self.store.query("SELECT spec_json FROM tasks WHERE task_id = 'task-1'")[
            0
        ]
        spec = json.loads(task["spec_json"])
        spec["evaluator_required"] = True
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE tasks SET spec_json = ? WHERE task_id = 'task-1'",
                (json.dumps(spec, sort_keys=True, separators=(",", ":")),),
            )
        self.evidence.record_claim(
            task_id="task-1",
            claim="an unreferenced independent PASS exists",
            evidence_state=EvidenceState.STRUCTURE,
            artifact_refs=self.claim.artifact_refs,
            verifier_session=self.evaluator,
            verifier_version="1",
            environment="local",
            evaluator_verdict=EvaluatorVerdict.PASS,
            non_claims=("not the referenced claim",),
        )
        item = self._item()
        with self.assertRaisesRegex(EvidenceError, "passing task evidence"):
            self.queue.advance(
                item.integration_id,
                target=IntegrationState.DELIVERED,
                actor=self.identities.release,
                evidence_refs=(self.claim.evidence_id,),
                reason="attempt to borrow evaluator PASS from another claim",
            )

    def test_only_delivered_tasks_satisfy_run_delivery_terminal_gate(self) -> None:
        run = self.store.query("SELECT * FROM runs WHERE run_id = 'run-1'")[0]
        for state in ("canceled", "deleted", "retired", "failed"):
            with self.subTest(state=state):
                with self.store.transaction(immediate=True) as connection:
                    connection.execute(
                        "UPDATE tasks SET state = ? WHERE task_id = 'task-1'",
                        (state,),
                    )
                    self.assertFalse(
                        self.kernel.guards._tasks_terminal(connection, run)
                    )
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE tasks SET state = 'delivered' WHERE task_id = 'task-1'"
            )
            self.assertTrue(self.kernel.guards._tasks_terminal(connection, run))

    def test_terminal_task_is_sealed_against_existing_integration_mutation(
        self,
    ) -> None:
        item = self._item()
        self.kernel.control_task(
            task_id="task-1",
            action="block",
            reason="owner stops integration",
            actor=self.identities.owner,
            idempotency_key="block-integration-task",
        )
        self.kernel.control_task(
            task_id="task-1",
            action="cancel",
            reason="owner cancels integration",
            actor=self.identities.owner,
            idempotency_key="cancel-integration-task",
        )
        with self.assertRaisesRegex(TransitionError, "sealed"):
            self.queue.advance(
                item.integration_id,
                target=IntegrationState.DELIVERED,
                actor=self.identities.release,
                evidence_refs=(self.claim.evidence_id,),
                reason="attempt terminal integration mutation",
            )


if __name__ == "__main__":
    unittest.main()
