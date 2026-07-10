"""Evaluator coverage for the durable, append-only SQLite event store."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any

from companyos_runtime.errors import IntegrityError
from companyos_runtime.kernel import RuntimeKernel
from companyos_runtime.replay import ProjectionReplayer
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import (
    EvidenceState,
    GoalSpec,
    canonical_json,
    content_hash,
)

from tests.identity_fixtures import IdentityFixture


class EventStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self._temporary_directory.name) / "runtime.sqlite3"
        self.store = SQLiteStore(self.database_path)
        self.store.initialize()

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    def _append_event(
        self,
        *,
        aggregate_type: str = "test_aggregate",
        aggregate_id: str = "run-1",
        expected_version: int = 0,
        project_id: str = "project-1",
        event_type: str = "goal_compiled",
        payload: dict[str, Any] | None = None,
        causation_id: str | None = None,
    ) -> dict[str, Any]:
        with self.store.transaction(immediate=True) as connection:
            return self.store.append_event(
                connection,
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                expected_version=expected_version,
                project_id=project_id,
                event_type=event_type,
                actor="evaluator",
                command_id=str(uuid.uuid4()),
                correlation_id="correlation-1",
                policy_version="policy-v1",
                payload=payload or {"state": event_type},
                causation_id=causation_id,
            )

    def _disable_update_protection(self) -> None:
        with self.store.transaction(immediate=True) as connection:
            connection.execute("DROP TRIGGER events_no_update")

    def test_aggregate_versions_are_gapless_and_conflicts_roll_back(self) -> None:
        first = self._append_event(expected_version=0)
        second = self._append_event(expected_version=1, event_type="run_ready")
        other = self._append_event(
            aggregate_id="run-2",
            expected_version=0,
            event_type="goal_compiled",
        )

        self.assertEqual(first["aggregate_version"], 1)
        self.assertEqual(second["aggregate_version"], 2)
        self.assertEqual(other["aggregate_version"], 1)

        with self.assertRaisesRegex(IntegrityError, "aggregate version conflict"):
            self._append_event(expected_version=1, event_type="stale-command")

        versions = self.store.query(
            "SELECT aggregate_version FROM events "
            "WHERE aggregate_type = ? AND aggregate_id = ? ORDER BY aggregate_version",
            ("test_aggregate", "run-1"),
        )
        self.assertEqual([row["aggregate_version"] for row in versions], [1, 2])

    def test_idempotent_result_survives_reopen_and_rejects_payload_conflict(
        self,
    ) -> None:
        event = self._append_event()
        original_digest = content_hash({"action": "compile", "value": 1})
        with self.store.transaction(immediate=True) as connection:
            self.store.save_idempotent_result(
                connection,
                project_id="project-1",
                scope="compile-goal",
                key="stable-command-key",
                payload_digest=original_digest,
                result={"goal_id": "goal-1", "state": "compiled"},
                event_id=event["event_id"],
            )

        reopened = SQLiteStore(self.database_path)
        with reopened.transaction() as connection:
            result = reopened.get_idempotent_result(
                connection,
                project_id="project-1",
                scope="compile-goal",
                key="stable-command-key",
                payload_digest=original_digest,
            )
        self.assertEqual(result, {"goal_id": "goal-1", "state": "compiled"})

        with reopened.transaction() as connection:
            with self.assertRaisesRegex(IntegrityError, "different payload"):
                reopened.get_idempotent_result(
                    connection,
                    project_id="project-1",
                    scope="compile-goal",
                    key="stable-command-key",
                    payload_digest=content_hash({"action": "compile", "value": 2}),
                )

    def test_events_table_rejects_update_and_delete(self) -> None:
        event = self._append_event()

        with self.assertRaisesRegex(sqlite3.IntegrityError, "events are append-only"):
            with self.store.transaction(immediate=True) as connection:
                connection.execute(
                    "UPDATE events SET actor = ? WHERE event_id = ?",
                    ("tampered-actor", event["event_id"]),
                )

        with self.assertRaisesRegex(sqlite3.IntegrityError, "events are append-only"):
            with self.store.transaction(immediate=True) as connection:
                connection.execute(
                    "DELETE FROM events WHERE event_id = ?", (event["event_id"],)
                )

        self.assertEqual(self.store.verify_event_chain(), 1)

    def test_payload_tampering_is_detected_even_if_database_guard_is_bypassed(
        self,
    ) -> None:
        event = self._append_event(payload={"state": "compiled", "approved": False})
        self._disable_update_protection()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE events SET payload_json = ? WHERE event_id = ?",
                ('{"approved":true,"state":"compiled"}', event["event_id"]),
            )

        with self.assertRaisesRegex(IntegrityError, "payload digest mismatch"):
            self.store.verify_event_chain()

    def test_event_envelope_tampering_is_detected_by_hash_chain(self) -> None:
        event = self._append_event()
        self._disable_update_protection()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE events SET actor = ? WHERE event_id = ?",
                ("forged-owner", event["event_id"]),
            )

        with self.assertRaisesRegex(IntegrityError, "event hash mismatch"):
            self.store.verify_event_chain()

    def test_causation_must_exist_and_is_recorded_after_its_cause(self) -> None:
        with self.assertRaisesRegex(IntegrityError, "causation event does not exist"):
            self._append_event(causation_id="missing-event")
        self.assertEqual(self.store.query("SELECT event_id FROM events"), [])

        cause = self._append_event(expected_version=0, event_type="goal_compiled")
        child = self._append_event(
            expected_version=1,
            event_type="run_ready",
            causation_id=cause["event_id"],
        )
        rows = self.store.query(
            "SELECT seq, event_id, causation_id FROM events ORDER BY seq"
        )
        self.assertEqual(
            [row["event_id"] for row in rows], [cause["event_id"], child["event_id"]]
        )
        self.assertLess(rows[0]["seq"], rows[1]["seq"])
        self.assertEqual(rows[1]["causation_id"], cause["event_id"])
        self.assertEqual(self.store.verify_event_chain(), 2)

    def test_database_persists_across_a_fresh_python_process(self) -> None:
        self._append_event(expected_version=0)
        repository_root = Path(__file__).resolve().parents[1]
        script = (
            "from companyos_runtime.store import SQLiteStore; "
            f"store = SQLiteStore({str(self.database_path)!r}); "
            "store.initialize(); "
            "print(store.verify_event_chain())"
        )
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-B", "-c", script],
            cwd=repository_root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "1")

    def test_raw_core_delivery_append_without_command_auth_context_is_rejected(
        self,
    ) -> None:
        identities = IdentityFixture(self.store)
        with self.assertRaisesRegex(IntegrityError, "opaque command authority"):
            with self.store.transaction(immediate=True) as connection:
                self.store.append_event(
                    connection,
                    aggregate_type="run",
                    aggregate_id="run-forged",
                    expected_version=0,
                    project_id="project-1",
                    run_id="run-forged",
                    event_type="delivery_confirmed",
                    actor=identities.release.principal_id,
                    command_id=str(uuid.uuid4()),
                    correlation_id="run-forged",
                    policy_version="policy-v1",
                    payload={"event": "delivery_confirmed"},
                )
        self.assertEqual(
            self.store.query(
                "SELECT event_id FROM events WHERE aggregate_id = ?",
                ("run-forged",),
            ),
            [],
        )

    def test_valid_privileged_bearer_and_forged_handler_cannot_append_core_event(
        self,
    ) -> None:
        identities = IdentityFixture(self.store)
        cases = (
            ("release", identities.release, "delivery_confirmed"),
            ("system", identities.system, "run_ready"),
        )
        for name, session, event_type in cases:
            with self.subTest(role=name):
                with self.assertRaisesRegex(IntegrityError, "opaque command authority"):
                    with self.store.transaction(immediate=True) as connection:
                        self.store.append_event(
                            connection,
                            aggregate_type="run",
                            aggregate_id=f"run-forged-{name}",
                            expected_version=0,
                            project_id="project-1",
                            run_id=f"run-forged-{name}",
                            event_type=event_type,
                            actor=session.principal_id,
                            auth_context={
                                "handler": "runtime_kernel",
                                "session_id": session.session_id,
                            },
                            auth_session=session,
                            command_authority=object(),
                            command_id=str(uuid.uuid4()),
                            correlation_id=f"run-forged-{name}",
                            policy_version="policy-v1",
                            payload={"event": event_type},
                        )
        self.assertEqual(
            self.store.query(
                "SELECT event_id FROM events WHERE aggregate_type = 'run'"
            ),
            [],
        )

    def test_repair_refuses_core_event_without_opaque_authority_provenance(
        self,
    ) -> None:
        identities = IdentityFixture(self.store)
        kernel = RuntimeKernel(self.store)
        kernel.create_goal(
            project_id="project-1",
            spec=GoalSpec(
                goal_id="goal-forged-repair",
                target_outcome="reject forged replay authority",
                success_evidence_states=(EvidenceState.RUNTIME,),
            ),
            actor=identities.owner,
            idempotency_key="goal-forged-repair",
        )
        event = self.store.query("SELECT * FROM events WHERE aggregate_type = 'goal'")[
            0
        ]
        auth = json.loads(event["auth_context_json"])
        auth.pop("command_authority_version")
        envelope = {
            "event_id": event["event_id"],
            "aggregate_type": event["aggregate_type"],
            "aggregate_id": event["aggregate_id"],
            "aggregate_version": event["aggregate_version"],
            "project_id": event["project_id"],
            "run_id": event["run_id"],
            "task_id": event["task_id"],
            "event_type": event["event_type"],
            "schema_version": event["schema_version"],
            "actor": event["actor"],
            "auth_context": auth,
            "command_id": event["command_id"],
            "idempotency_key": event["idempotency_key"],
            "correlation_id": event["correlation_id"],
            "causation_id": event["causation_id"],
            "policy_version": event["policy_version"],
            "occurred_at": event["occurred_at"],
            "recorded_at": event["recorded_at"],
            "confidentiality": event["confidentiality"],
            "payload_digest": event["payload_digest"],
            "previous_event_hash": event["previous_event_hash"],
        }
        forged_hash = content_hash(
            event["previous_event_hash"] + canonical_json(envelope)
        )
        self._disable_update_protection()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE events SET auth_context_json = ?, event_hash = ? "
                "WHERE event_id = ?",
                (canonical_json(auth), forged_hash, event["event_id"]),
            )
            connection.execute(
                "DELETE FROM goals WHERE goal_id = ?", ("goal-forged-repair",)
            )

        with self.assertRaisesRegex(IntegrityError, "authority metadata invalid"):
            ProjectionReplayer(self.store).repair(actor=identities.system)
        self.assertEqual(self.store.query("SELECT goal_id FROM goals"), [])


if __name__ == "__main__":
    unittest.main()
