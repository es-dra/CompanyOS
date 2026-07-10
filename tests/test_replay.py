"""Evaluator tests for deterministic core-projection replay and repair."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from companyos_runtime.errors import IntegrityError
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


class ProjectionReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        self.kernel = RuntimeKernel(self.store)
        self.kernel.initialize()
        self.identities = IdentityFixture(self.store)
        self._seed_event_history()
        self.replayer = ProjectionReplayer(self.store)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _seed_event_history(self) -> None:
        goal = GoalSpec(
            goal_id="goal-1",
            target_outcome="exercise deterministic replay",
            success_evidence_states=(EvidenceState.RUNTIME,),
            read_scope=("workspace://project/public/**",),
            write_scope=("workspace://project/output/**",),
        )
        task = TaskSpec(
            task_id="task-1",
            goal_id="goal-1",
            objective="create a replayable task",
            expected_delta="quality",
            primary_surface="workspace://project/output/report.json",
            evidence_target=EvidenceState.RUNTIME,
            read_scope=("workspace://project/public/input.json",),
            write_scope=("workspace://project/output/report.json",),
            integration_required=False,
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

    def _fail_once(self) -> tuple[TaskScheduler, str]:
        scheduler = TaskScheduler(
            self.store, retry_base_seconds=60, retry_max_seconds=60
        )
        worker = self.identities.worker_named("replay-worker")
        claim = scheduler.claim_next(project_id="project-1", worker=worker)
        self.assertIsNotNone(claim)
        assert claim is not None
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
        scheduler.start(claim, worker=worker)
        failure = scheduler.fail(
            claim,
            worker=worker,
            failure_class="ReplayFailure",
            message="stable replay failure",
        )
        return scheduler, failure.fingerprint

    def test_replay_is_deterministic_and_matches_current_projections(self) -> None:
        first = self.replayer.replay()
        second = self.replayer.replay()
        verified = self.replayer.verify()

        self.assertEqual(first, second)
        self.assertEqual(verified, first)
        self.assertEqual(first.runs["run-1"]["loop_state"], "ready")
        self.assertEqual(first.tasks["task-1"]["state"], "ready")
        self.assertEqual(self.store.verify_event_chain(), 5)

    def test_replay_rejects_malformed_structured_evidence_linkage(self) -> None:
        tasks = {
            "task-1": {
                "state": TaskState.EVIDENCE_PENDING.value,
                "aggregate_version": 3,
            }
        }
        row = {
            "aggregate_id": "task-1",
            "aggregate_version": 4,
            "event_type": "task_state_changed",
            "recorded_at": "2026-07-10T00:00:00Z",
        }
        payload = {
            "from": TaskState.EVIDENCE_PENDING.value,
            "target": TaskState.INTEGRATION_PENDING.value,
            "reason": "free text is not evidence authority",
            "accepted_evidence_id": "",
        }
        with self.assertRaisesRegex(IntegrityError, "accepted-evidence linkage"):
            self.replayer._apply_task(tasks, {}, {}, row, payload)

    def test_verify_detects_projection_tamper_and_repair_is_idempotent(self) -> None:
        event_count = self.store.verify_event_chain()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE runs SET loop_state = 'delivered', aggregate_version = 999 WHERE run_id = 'run-1'"
            )
            connection.execute(
                "UPDATE tasks SET state = 'retired', aggregate_version = 999 WHERE task_id = 'task-1'"
            )

        with self.assertRaisesRegex(IntegrityError, "projection mismatch"):
            self.replayer.verify()

        repaired = self.replayer.repair(actor=self.identities.system)
        self.assertEqual(repaired.runs["run-1"]["loop_state"], "ready")
        self.assertEqual(repaired.tasks["task-1"]["state"], "ready")
        self.replayer.verify()

        repaired_again = self.replayer.repair(actor=self.identities.system)
        self.assertEqual(repaired_again, repaired)
        self.assertEqual(self.store.verify_event_chain(), event_count)

    def test_repair_recreates_a_missing_projection_without_changing_events(
        self,
    ) -> None:
        event_count = self.store.verify_event_chain()
        with self.store.transaction(immediate=True) as connection:
            connection.execute("DELETE FROM tasks WHERE task_id = 'task-1'")
        with self.assertRaisesRegex(IntegrityError, "projection identity mismatch"):
            self.replayer.verify()

        repaired = self.replayer.repair(actor=self.identities.system)
        self.assertIn("task-1", repaired.tasks)
        self.assertEqual(self.kernel.get_task("task-1")["state"], "ready")
        self.assertEqual(self.store.verify_event_chain(), event_count)

    def test_verify_detects_scheduler_operational_projection_tamper(self) -> None:
        _, fingerprint = self._fail_once()
        self.replayer.verify()

        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE attempts SET attempt_number = 2 WHERE task_id = 'task-1'"
            )
            connection.execute(
                "UPDATE tasks SET attempt_count = 2 WHERE task_id = 'task-1'"
            )
        with self.assertRaisesRegex(IntegrityError, "not gapless"):
            self.replayer.verify()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE attempts SET attempt_number = 1 WHERE task_id = 'task-1'"
            )
            connection.execute(
                "UPDATE tasks SET attempt_count = 1 WHERE task_id = 'task-1'"
            )

        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE tasks SET last_error_fingerprint = 'tampered' "
                "WHERE task_id = 'task-1'"
            )
        with self.assertRaisesRegex(IntegrityError, "last_error_fingerprint"):
            self.replayer.verify()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE tasks SET last_error_fingerprint = ? WHERE task_id = 'task-1'",
                (fingerprint,),
            )
            connection.execute(
                "UPDATE negative_results SET fingerprint = 'tampered-negative' "
                "WHERE task_id = 'task-1'"
            )
        with self.assertRaisesRegex(IntegrityError, "last_error_fingerprint"):
            self.replayer.verify()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE negative_results SET fingerprint = ? WHERE task_id = 'task-1'",
                (fingerprint,),
            )
            connection.execute(
                "UPDATE tasks SET due_at = NULL WHERE task_id = 'task-1'"
            )
        with self.assertRaisesRegex(IntegrityError, "due_at is required"):
            self.replayer.verify()

    def test_repair_refuses_missing_task_with_scheduler_rows(self) -> None:
        scheduler = TaskScheduler(self.store)
        worker = self.identities.worker_named("missing-task-worker")
        claim = scheduler.claim_next(project_id="project-1", worker=worker)
        self.assertIsNotNone(claim)
        event_count = self.store.verify_event_chain()

        raw = sqlite3.connect(self.store.path)
        try:
            raw.execute("PRAGMA foreign_keys = OFF")
            raw.execute("DELETE FROM tasks WHERE task_id = 'task-1'")
            raw.commit()
        finally:
            raw.close()

        with self.assertRaisesRegex(IntegrityError, "secondary operational rows"):
            self.replayer.repair(actor=self.identities.system)
        self.assertEqual(
            self.store.query("SELECT COUNT(*) AS count FROM tasks")[0]["count"], 0
        )
        self.assertEqual(self.store.verify_event_chain(), event_count)

    def test_failed_operational_repair_rolls_back_core_projection_writes(self) -> None:
        self._fail_once()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE tasks SET state = 'retired', aggregate_version = 999, "
                "attempt_count = 9 WHERE task_id = 'task-1'"
            )

        with self.assertRaisesRegex(IntegrityError, "attempt_count"):
            self.replayer.repair(actor=self.identities.system)

        task = self.store.query(
            "SELECT state, aggregate_version, attempt_count FROM tasks "
            "WHERE task_id = 'task-1'"
        )[0]
        self.assertEqual(task["state"], "retired")
        self.assertEqual(task["aggregate_version"], 999)
        self.assertEqual(task["attempt_count"], 9)

    def test_repair_refuses_to_delete_projection_without_source_events(self) -> None:
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "INSERT INTO goals(goal_id, project_id, state, spec_json, aggregate_version, created_at, updated_at) "
                "VALUES ('orphan-goal', 'project-1', 'compiled', '{}', 1, 'now', 'now')"
            )
        with self.assertRaisesRegex(
            IntegrityError, "refusing to delete projection rows without events"
        ):
            self.replayer.repair(actor=self.identities.system)


if __name__ == "__main__":
    unittest.main()
