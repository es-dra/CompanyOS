"""Independent evaluator tests for runtime-surface freshness semantics."""

from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from companyos_runtime.errors import AuthorizationError, FreshnessError
from companyos_runtime.identity import Role
from companyos_runtime.observations import ObservationRegistry
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import (
    EvidenceState,
    GoalSpec,
    RuntimeSurfaceSpec,
    canonical_json,
    utc_now,
)

from tests.identity_fixtures import IdentityFixture


class ObservationRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        self.store.initialize()
        self.identities = IdentityFixture(self.store)
        self.requirement = RuntimeSurfaceSpec(
            surface_key="service:api",
            target_identity="commit:abc123",
            allowed_probes=("process_commit_probe",),
            max_ttl_seconds=60,
            trigger_event_required=False,
        )
        self._seed_run()
        self.observations = ObservationRegistry(self.store)
        self.now = datetime.now(UTC)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _seed_run(self) -> None:
        now = utc_now()
        goal = GoalSpec(
            goal_id="goal-1",
            target_outcome="verify a declared runtime surface",
            success_evidence_states=(EvidenceState.RUNTIME,),
            required_runtime_surfaces=(self.requirement,),
        )
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "INSERT INTO goals VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "goal-1",
                    "project-1",
                    "ready",
                    canonical_json(goal.to_dict()),
                    1,
                    now,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("run-1", "goal-1", "project-1", "ready", "policy-v1", 1, now, now),
            )

    def _record(self, **overrides: Any):
        values: dict[str, Any] = {
            "project_id": "project-1",
            "run_id": "run-1",
            "surface_key": "service:api",
            "target_identity": "commit:abc123",
            "observer": self.identities.observer,
            "probe_name": "process_commit_probe",
            "probe_version": "1",
            "status": "healthy",
            "value": {"loaded_commit": "abc123", "port": 8790},
            "ttl_seconds": 60,
            "observed_at": self.now,
        }
        values.update(overrides)
        return self.observations.record(**values)

    def test_healthy_matching_observation_passes_freshness_gate(self) -> None:
        recorded = self._record()
        result = self.observations.require_fresh(
            run_id="run-1",
            required_surfaces=(self.requirement,),
            as_of=self.now + timedelta(seconds=1),
        )
        self.assertEqual(result["service:api"].observation_id, recorded.observation_id)
        self.assertEqual(result["service:api"].value["loaded_commit"], "abc123")

    def test_missing_observation_is_rejected(self) -> None:
        with self.assertRaisesRegex(FreshnessError, "service:api: missing"):
            self.observations.require_fresh(
                run_id="run-1",
                required_surfaces=(self.requirement,),
                as_of=self.now,
            )

    def test_expired_observation_is_rejected(self) -> None:
        self._record(ttl_seconds=1)
        with self.assertRaisesRegex(FreshnessError, "stale since"):
            self.observations.require_fresh(
                run_id="run-1",
                required_surfaces=(self.requirement,),
                as_of=self.now + timedelta(seconds=2),
            )

    def test_unhealthy_or_unknown_observation_is_rejected(self) -> None:
        for status in ("degraded", "unhealthy", "failed", "unknown"):
            with self.subTest(status=status):
                temp = tempfile.TemporaryDirectory()
                try:
                    store = SQLiteStore(Path(temp.name) / "runtime.db")
                    store.initialize()
                    identities = IdentityFixture(store)
                    now_text = utc_now()
                    requirement = RuntimeSurfaceSpec(
                        surface_key="surface",
                        target_identity="target",
                        allowed_probes=("health_probe",),
                        max_ttl_seconds=60,
                        trigger_event_required=False,
                    )
                    goal = GoalSpec(
                        goal_id="goal",
                        target_outcome="evaluate unhealthy freshness",
                        success_evidence_states=(EvidenceState.RUNTIME,),
                        required_runtime_surfaces=(requirement,),
                    )
                    with store.transaction(immediate=True) as connection:
                        connection.execute(
                            "INSERT INTO goals VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (
                                "goal",
                                "project",
                                "ready",
                                canonical_json(goal.to_dict()),
                                1,
                                now_text,
                                now_text,
                            ),
                        )
                        connection.execute(
                            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                "run",
                                "goal",
                                "project",
                                "ready",
                                "policy-v1",
                                1,
                                now_text,
                                now_text,
                            ),
                        )
                    registry = ObservationRegistry(store)
                    registry.record(
                        project_id="project",
                        run_id="run",
                        surface_key="surface",
                        target_identity="target",
                        observer=identities.observer,
                        probe_name="health_probe",
                        probe_version="1",
                        status=status,
                        value={"status": status},
                        ttl_seconds=60,
                    )
                    with self.assertRaisesRegex(FreshnessError, f"status={status}"):
                        registry.require_fresh(
                            run_id="run",
                            required_surfaces=(requirement,),
                        )
                finally:
                    temp.cleanup()

    def test_target_identity_mismatch_is_rejected_on_record_and_freshness(self) -> None:
        with self.assertRaisesRegex(FreshnessError, "does not match"):
            self._record(target_identity="commit:old")
        recorded = self._record()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE runtime_observations SET target_identity = ? WHERE observation_id = ?",
                ("commit:old", recorded.observation_id),
            )
        with self.assertRaisesRegex(FreshnessError, "commit:old != commit:abc123"):
            self.observations.require_fresh(
                run_id="run-1",
                required_surfaces=(self.requirement,),
                as_of=self.now + timedelta(seconds=1),
            )

    def test_contradictory_observations_at_the_same_instant_are_rejected(self) -> None:
        self._record(value={"loaded_commit": "abc123", "port": 8790})
        self._record(value={"loaded_commit": "abc123", "port": 9000})
        with self.assertRaisesRegex(FreshnessError, "contradictory observations"):
            self.observations.require_fresh(
                run_id="run-1",
                required_surfaces=(self.requirement,),
                as_of=self.now + timedelta(seconds=1),
            )

    def test_documentation_names_cannot_be_used_as_runtime_probes(self) -> None:
        for probe_name in (
            "documentation",
            "readme",
            "static_doc",
            "declared_state",
            "README.md",
            "docs/runtime-status.md",
        ):
            with self.subTest(probe_name=probe_name):
                with self.assertRaisesRegex(FreshnessError, "not a runtime probe"):
                    self._record(probe_name=probe_name)

    def test_observer_must_be_authenticated_and_remain_trusted(self) -> None:
        with self.assertRaisesRegex(AuthorizationError, "authenticated session"):
            self._record(observer="probe-forgery")

        self._record()
        self.identities.manager.set_roles(
            self.identities.owner,
            display_name="test-control",
            roles={Role.OWNER, Role.SYSTEM, Role.RELEASE},
        )
        with self.assertRaisesRegex(FreshnessError, "not currently trusted"):
            self.observations.require_fresh(
                run_id="run-1",
                required_surfaces=(self.requirement,),
                as_of=self.now + timedelta(seconds=1),
            )


if __name__ == "__main__":
    unittest.main()
