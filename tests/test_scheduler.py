"""Evaluator tests for bounded scheduler concurrency, retry, and recovery."""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from companyos_runtime.errors import LeaseError
from companyos_runtime.identity import VerifiedPrincipal
from companyos_runtime.kernel import RuntimeKernel
from companyos_runtime.replay import ProjectionReplayer
from companyos_runtime.scheduler import TaskScheduler
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import (
    EvidenceState,
    GoalSpec,
    LoopEvent,
    LoopState,
    TaskSpec,
    TaskState,
)

from tests.identity_fixtures import IdentityFixture


class TaskSchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        self.kernel = RuntimeKernel(self.store)
        self.kernel.initialize()
        self.identities = IdentityFixture(self.store)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _seed_task(self, *, max_attempts: int = 2) -> None:
        goal = GoalSpec(
            goal_id="goal-1",
            target_outcome="exercise bounded scheduling",
            success_evidence_states=(EvidenceState.RUNTIME,),
        )
        task = TaskSpec(
            task_id="task-1",
            goal_id="goal-1",
            objective="execute one bounded scheduler task",
            expected_delta="quality",
            primary_surface="local://scheduler",
            evidence_target=EvidenceState.RUNTIME,
            integration_required=False,
            max_attempts=max_attempts,
        )
        self.kernel.create_goal(
            project_id="project-1",
            spec=goal,
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
            spec=task,
            actor=self.identities.owner,
            idempotency_key="task-add",
        )
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

    def _authorize_start(self, claim, worker: VerifiedPrincipal) -> None:
        if self.kernel.get_run("run-1")["loop_state"] == LoopState.READY.value:
            self.kernel.advance_loop(
                run_id="run-1",
                event=LoopEvent.TASK_STARTED,
                actor=worker,
                idempotency_key=f"run-start-{claim.attempt_id}",
                payload={
                    "task_id": claim.task_id,
                    "resource_key": claim.resource_key,
                    "holder": worker.principal_id,
                    "fence": claim.fence,
                },
            )

    def test_concurrent_claim_has_exactly_one_winner(self) -> None:
        self._seed_task()
        scheduler = TaskScheduler(self.store, retry_base_seconds=1, retry_max_seconds=2)
        barrier = threading.Barrier(3)
        results = []
        failures = []
        result_lock = threading.Lock()

        workers = (
            self.identities.worker_named("worker-a"),
            self.identities.worker_named("worker-b"),
        )

        def claim(worker: VerifiedPrincipal) -> None:
            try:
                barrier.wait(timeout=10)
                result = scheduler.claim_next(project_id="project-1", worker=worker)
                with result_lock:
                    results.append(result)
            except (
                Exception
            ) as exc:  # evaluator must report any unexpected race failure
                with result_lock:
                    failures.append(exc)

        threads = [threading.Thread(target=claim, args=(worker,)) for worker in workers]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=15)

        self.assertFalse(failures, failures)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        winners = [result for result in results if result is not None]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(results), 2)
        self.assertEqual(
            self.kernel.get_task("task-1")["state"], TaskState.LEASED.value
        )
        self.assertEqual(len(self.store.query("SELECT * FROM attempts")), 1)
        self.assertEqual(
            len(self.store.query("SELECT * FROM leases WHERE released_at IS NULL")), 1
        )
        ProjectionReplayer(self.store).verify()

    def test_failures_back_off_then_open_circuit_at_attempt_limit(self) -> None:
        self._seed_task(max_attempts=2)
        scheduler = TaskScheduler(self.store, retry_base_seconds=1, retry_max_seconds=2)
        worker_one = self.identities.worker_named("worker-one")
        worker_two = self.identities.worker_named("worker-two")
        worker_three = self.identities.worker_named("worker-three")

        first = scheduler.claim_next(project_id="project-1", worker=worker_one)
        self.assertIsNotNone(first)
        assert first is not None
        self._authorize_start(first, worker_one)
        scheduler.start(first, worker=worker_one)
        first_failure = scheduler.fail(
            first,
            worker=worker_one,
            failure_class="DeterministicFailure",
            message="same stable failure",
        )
        self.assertIs(first_failure.state, TaskState.RETRY_PENDING)
        self.assertFalse(first_failure.circuit_open)
        self.assertIsNotNone(first_failure.retry_due_at)

        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE tasks SET due_at = '2000-01-01T00:00:00.000Z' WHERE task_id = 'task-1'"
            )
        self.assertEqual(
            scheduler.promote_due_retries(
                project_id="project-1", actor=self.identities.system
            ),
            1,
        )

        second = scheduler.claim_next(project_id="project-1", worker=worker_two)
        self.assertIsNotNone(second)
        assert second is not None
        self.assertEqual(second.attempt_number, 2)
        scheduler.start(second, worker=worker_two)
        second_failure = scheduler.fail(
            second,
            worker=worker_two,
            failure_class="DeterministicFailure",
            message="same stable failure",
        )
        self.assertIs(second_failure.state, TaskState.FAILED)
        self.assertTrue(second_failure.circuit_open)
        self.assertIsNone(second_failure.retry_due_at)
        self.assertIsNone(
            scheduler.claim_next(project_id="project-1", worker=worker_three)
        )

        task = self.kernel.get_task("task-1")
        self.assertEqual(task["state"], TaskState.FAILED.value)
        self.assertEqual(task["attempt_count"], 2)
        negative = self.store.query(
            "SELECT recurrence_count FROM negative_results WHERE task_id = 'task-1'"
        )
        self.assertEqual(negative, [{"recurrence_count": 2}])
        replayed = ProjectionReplayer(self.store).verify()
        self.assertEqual(replayed.tasks["task-1"]["state"], TaskState.FAILED.value)

    def test_stale_claim_is_rejected_and_reaped_into_retry(self) -> None:
        self._seed_task(max_attempts=2)
        scheduler = TaskScheduler(self.store, retry_base_seconds=1, retry_max_seconds=2)
        worker = self.identities.worker_named("worker-stale")
        claim = scheduler.claim_next(
            project_id="project-1", worker=worker, ttl_seconds=60
        )
        self.assertIsNotNone(claim)
        assert claim is not None

        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE leases SET issued_at = '1999-12-31T23:59:00.000Z', "
                "expires_at = '2000-01-01T00:00:00.000Z' WHERE resource_key = ?",
                (claim.resource_key,),
            )
        with self.assertRaisesRegex(LeaseError, "task claim is stale"):
            scheduler.start(claim, worker=worker)

        self.assertEqual(
            scheduler.reap_expired(
                project_id="project-1", actor=self.identities.system
            ),
            1,
        )
        self.assertEqual(
            self.kernel.get_task("task-1")["state"], TaskState.RETRY_PENDING.value
        )
        attempt = self.store.query(
            "SELECT state, ended_at FROM attempts WHERE attempt_id = ?",
            (claim.attempt_id,),
        )[0]
        self.assertEqual(attempt["state"], "abandoned")
        self.assertIsNotNone(attempt["ended_at"])
        with self.assertRaises(LeaseError):
            scheduler.start(claim, worker=worker)

        replayed = ProjectionReplayer(self.store).verify()
        self.assertEqual(
            replayed.tasks["task-1"]["state"], TaskState.RETRY_PENDING.value
        )

    def test_start_requires_parent_run_task_started_gate(self) -> None:
        self._seed_task()
        scheduler = TaskScheduler(self.store)
        worker = self.identities.worker_named("worker-gated-start")
        claim = scheduler.claim_next(project_id="project-1", worker=worker)
        self.assertIsNotNone(claim)
        assert claim is not None
        with self.assertRaisesRegex(LeaseError, "parent run is not executable"):
            scheduler.start(claim, worker=worker)
        self.assertEqual(
            self.kernel.get_run("run-1")["loop_state"], LoopState.READY.value
        )
        self.assertEqual(
            self.kernel.get_task("task-1")["state"], TaskState.LEASED.value
        )


if __name__ == "__main__":
    unittest.main()
