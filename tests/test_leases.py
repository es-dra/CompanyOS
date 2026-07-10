from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from companyos_runtime.errors import LeaseError
from companyos_runtime.identity import VerifiedPrincipal
from companyos_runtime.leases import LeaseManager
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import canonical_json, utc_now

from tests.identity_fixtures import IdentityFixture


class LeaseManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        self.store.initialize()
        self.identities = IdentityFixture(self.store)
        self._seed_task()
        self.leases = LeaseManager(self.store)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _seed_task(self) -> None:
        now = utc_now()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "INSERT INTO goals VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("goal-1", "project-1", "ready", canonical_json({}), 1, now, now),
            )
            connection.execute(
                "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("run-1", "goal-1", "project-1", "ready", "policy-v1", 1, now, now),
            )
            connection.execute(
                """
                INSERT INTO tasks(
                    task_id, goal_id, run_id, project_id, state, spec_json,
                    aggregate_version, attempt_count, due_at,
                    last_error_fingerprint, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                """,
                (
                    "task-1",
                    "goal-1",
                    "run-1",
                    "project-1",
                    "ready",
                    canonical_json({}),
                    1,
                    0,
                    now,
                    now,
                ),
            )

    def _acquire(self, holder: VerifiedPrincipal):
        return self.leases.acquire(
            resource_key="repo://one",
            project_id="project-1",
            task_id="task-1",
            holder=holder,
            ttl_seconds=300,
        )

    def test_concurrent_acquisition_has_one_winner(self) -> None:
        barrier = threading.Barrier(2)
        winners = []
        errors = []
        workers = (
            self.identities.worker_named("worker-one"),
            self.identities.worker_named("worker-two"),
        )

        def acquire(holder: VerifiedPrincipal) -> None:
            try:
                barrier.wait()
                winners.append(self._acquire(holder))
            except LeaseError as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=acquire, args=(worker,)) for worker in workers
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(winners), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(winners[0].fence, 1)
        self.assertEqual(self.leases.current_fence("repo://one"), 1)

    def test_same_holder_acquire_is_idempotent_but_does_not_renew(self) -> None:
        worker = self.identities.worker
        first = self._acquire(worker)
        replay = self._acquire(worker)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.fence, first.fence)
        self.assertEqual(replay.expires_at, first.expires_at)

    def test_release_and_takeover_increments_fence_and_rejects_stale_holder(
        self,
    ) -> None:
        worker_one = self.identities.worker_named("worker-one")
        worker_two = self.identities.worker_named("worker-two")
        first = self._acquire(worker_one)
        self.leases.release(
            resource_key="repo://one",
            project_id="project-1",
            task_id="task-1",
            holder=worker_one,
            fence=first.fence,
        )
        second = self._acquire(worker_two)
        self.assertEqual(second.fence, first.fence + 1)

        with self.assertRaises(LeaseError):
            self.leases.renew(
                resource_key="repo://one",
                project_id="project-1",
                task_id="task-1",
                holder=worker_one,
                fence=first.fence,
                ttl_seconds=300,
            )
        with self.assertRaises(LeaseError):
            self.leases.release(
                resource_key="repo://one",
                project_id="project-1",
                task_id="task-1",
                holder=worker_one,
                fence=first.fence,
            )
        with self.assertRaises(LeaseError):
            self.leases.require_current_fence(
                resource_key="repo://one",
                project_id="project-1",
                task_id="task-1",
                holder=worker_one,
                fence=first.fence,
            )

        current = self.leases.require_current_fence(
            resource_key="repo://one",
            project_id="project-1",
            task_id="task-1",
            holder=worker_two,
            fence=second.fence,
        )
        self.assertEqual(current.fence, second.fence)

    def test_expired_lease_requires_takeover_not_renewal(self) -> None:
        worker_one = self.identities.worker_named("worker-one")
        worker_two = self.identities.worker_named("worker-two")
        first = self._acquire(worker_one)
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                """
                UPDATE leases
                SET issued_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-2 seconds'),
                    expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 second')
                WHERE resource_key = ?
                """,
                ("repo://one",),
            )
        with self.assertRaises(LeaseError):
            self.leases.renew(
                resource_key="repo://one",
                project_id="project-1",
                task_id="task-1",
                holder=worker_one,
                fence=first.fence,
                ttl_seconds=300,
            )
        second = self._acquire(worker_two)
        self.assertEqual(second.fence, first.fence + 1)

    def test_renew_and_release_require_exact_scope(self) -> None:
        worker = self.identities.worker
        other = self.identities.worker_named("worker-other")
        lease = self._acquire(worker)
        renewed = self.leases.renew(
            resource_key="repo://one",
            project_id="project-1",
            task_id="task-1",
            holder=worker,
            fence=lease.fence,
            ttl_seconds=600,
        )
        self.assertEqual(renewed.fence, lease.fence)
        with self.assertRaises(LeaseError):
            self.leases.require_current_fence(
                resource_key="repo://one",
                project_id="project-1",
                task_id="task-1",
                holder=other,
                fence=lease.fence,
            )

        released = self.leases.release(
            resource_key="repo://one",
            project_id="project-1",
            task_id="task-1",
            holder=worker,
            fence=lease.fence,
        )
        self.assertIsNotNone(released.released_at)
        replay = self.leases.release(
            resource_key="repo://one",
            project_id="project-1",
            task_id="task-1",
            holder=worker,
            fence=lease.fence,
        )
        self.assertTrue(replay.replayed)


if __name__ == "__main__":
    unittest.main()
