"""Backup, operator snapshot, and project-adapter conformance coverage."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import companyos_runtime.backup as backup_module
from companyos_runtime.adapters import run_adapter_conformance
from companyos_runtime.backup import create_online_backup, restore_backup
from companyos_runtime.errors import IntegrityError
from companyos_runtime.fake_provider import FakeProvider
from companyos_runtime.operator import operator_snapshot
from companyos_runtime.store import SQLiteStore


class RuntimeBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "runtime.db"
        self.store = SQLiteStore(self.source)
        self.store.initialize()
        with self.store.transaction(immediate=True) as connection:
            self.store.append_event(
                connection,
                aggregate_type="operations_test",
                aggregate_id="backup-1",
                expected_version=0,
                project_id="project-1",
                event_type="snapshot_ready",
                actor="test-system",
                command_id=str(uuid.uuid4()),
                correlation_id="backup-1",
                policy_version="test-policy",
                payload={"private_marker": "must-not-appear-in-operator-output"},
            )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_online_backup_manifest_and_default_new_target_restore(self) -> None:
        backup = self.root / "runtime-backup.db"
        manifest = create_online_backup(self.source, backup)

        self.assertEqual(manifest["event_log"]["count"], 1)
        self.assertEqual(manifest["verification"]["event_chain"], "passed")
        self.assertFalse(manifest["recovery_set"]["complete"])
        self.assertFalse(manifest["recovery_set"]["external_adapter_receipts_included"])
        self.assertNotIn(str(self.root), json.dumps(manifest))
        self.assertNotIn("runtime-backup.db", json.dumps(manifest))
        self.assertIn(
            "cryptographically_attested_backup",
            manifest["claim_boundary"]["non_claims"],
        )
        self.assertTrue(Path(str(backup) + ".manifest.json").is_file())
        self.assertFalse(Path(str(backup) + "-wal").exists())
        self.assertFalse(Path(str(backup) + "-shm").exists())

        restored = restore_backup(backup)
        restored_path = self.root / "runtime-backup.restored.db"
        self.assertTrue(restored_path.is_file())
        self.assertFalse(Path(str(restored_path) + "-wal").exists())
        self.assertEqual(restored["status"], "restored_verified")
        self.assertEqual(restored["event_log"], manifest["event_log"])
        self.assertEqual(
            restored["verification"]["core_projection_replay_readback"], "passed"
        )
        self.assertNotIn(str(self.root), json.dumps(restored))
        self.assertNotIn("runtime-backup.db", json.dumps(restored))

    def test_backup_and_restore_never_overwrite_existing_or_sidecar_state(self) -> None:
        missing_source = self.root / "missing.db"
        missing_target = self.root / "missing-backup.db"
        with self.assertRaisesRegex(IntegrityError, "existing regular file"):
            create_online_backup(missing_source, missing_target)
        self.assertFalse(missing_source.exists())
        self.assertFalse(missing_target.exists())

        backup = self.root / "runtime-backup.db"
        backup.write_bytes(b"owner-data")
        with self.assertRaisesRegex(IntegrityError, "refusing to overwrite"):
            create_online_backup(self.source, backup)
        self.assertEqual(backup.read_bytes(), b"owner-data")

        backup.unlink()
        create_online_backup(self.source, backup)
        target = self.root / "restored.db"
        target.write_bytes(b"unknown-database")
        with self.assertRaisesRegex(IntegrityError, "refusing to overwrite"):
            restore_backup(backup, target_database=target)
        self.assertEqual(target.read_bytes(), b"unknown-database")

        target.unlink()
        sidecar = Path(str(target) + "-wal")
        sidecar.write_bytes(b"unknown-wal")
        with self.assertRaisesRegex(IntegrityError, "existing SQLite sidecar"):
            restore_backup(backup, target_database=target)
        self.assertEqual(sidecar.read_bytes(), b"unknown-wal")

    def test_exclusive_create_races_never_delete_the_competing_file(self) -> None:
        backup = self.root / "runtime-backup.db"
        real_open = os.open

        def race_backup_create(path, flags, mode=0o777):
            if Path(path) == backup and flags & os.O_EXCL:
                backup.write_bytes(b"competing-backup")
            return real_open(path, flags, mode)

        with patch.object(backup_module.os, "open", side_effect=race_backup_create):
            with self.assertRaisesRegex(IntegrityError, "appeared concurrently"):
                create_online_backup(self.source, backup)
        self.assertEqual(backup.read_bytes(), b"competing-backup")

        backup.unlink()
        manifest = Path(str(backup) + ".manifest.json")

        def race_manifest_create(path, flags, mode=0o777):
            if Path(path) == manifest and flags & os.O_EXCL:
                manifest.write_bytes(b"competing-manifest")
            return real_open(path, flags, mode)

        with patch.object(backup_module.os, "open", side_effect=race_manifest_create):
            with self.assertRaisesRegex(IntegrityError, "appeared concurrently"):
                create_online_backup(self.source, backup)
        self.assertEqual(manifest.read_bytes(), b"competing-manifest")
        self.assertFalse(backup.exists())

    def test_failure_cleanup_preserves_replacement_after_successful_create(
        self,
    ) -> None:
        backup = self.root / "runtime-backup.db"
        replacement = b"replacement-owned-by-another-worker"

        def replace_backup_before_failure(path: Path):
            path.unlink()
            path.write_bytes(replacement)
            raise IntegrityError("injected verification failure")

        with patch.object(
            backup_module,
            "_inspect_database",
            side_effect=replace_backup_before_failure,
        ):
            with self.assertRaisesRegex(
                IntegrityError, "injected verification failure"
            ):
                create_online_backup(self.source, backup)
        self.assertEqual(backup.read_bytes(), replacement)

        backup.unlink()
        create_online_backup(self.source, backup)
        target = self.root / "restored.db"
        original_inspect = backup_module._inspect_database

        def replace_restore_before_failure(path: Path):
            if path == target:
                path.unlink()
                path.write_bytes(replacement)
                raise IntegrityError("injected restore verification failure")
            return original_inspect(path)

        with patch.object(
            backup_module,
            "_inspect_database",
            side_effect=replace_restore_before_failure,
        ):
            with self.assertRaisesRegex(
                IntegrityError, "injected restore verification failure"
            ):
                restore_backup(backup, target_database=target)
        self.assertEqual(target.read_bytes(), replacement)

    def test_restore_rejects_tampered_backup_and_manifest(self) -> None:
        backup = self.root / "runtime-backup.db"
        create_online_backup(self.source, backup)
        manifest_path = Path(str(backup) + ".manifest.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["backup_sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        target = self.root / "restored.db"
        with self.assertRaisesRegex(IntegrityError, "does not match"):
            restore_backup(backup, target_database=target)
        self.assertFalse(target.exists())

        manifest.pop("verification")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(IntegrityError, "shape is invalid"):
            restore_backup(backup, target_database=target)
        self.assertFalse(target.exists())

        create_online_backup(self.source, self.root / "second-backup.db")
        second = self.root / "second-backup.db"
        second_manifest = Path(str(second) + ".manifest.json")
        tampered_boundary = json.loads(second_manifest.read_text(encoding="utf-8"))
        tampered_boundary["recovery_set"]["complete"] = True
        second_manifest.write_text(json.dumps(tampered_boundary), encoding="utf-8")
        with self.assertRaisesRegex(IntegrityError, "recovery-set boundary"):
            restore_backup(second, target_database=target)
        self.assertFalse(target.exists())

    def test_restore_rejects_projection_rows_without_source_events(self) -> None:
        backup = self.root / "runtime-backup.db"
        create_online_backup(self.source, backup)
        connection = sqlite3.connect(backup)
        try:
            connection.execute(
                "INSERT INTO goals(goal_id, project_id, state, spec_json, aggregate_version, created_at, updated_at) "
                "VALUES ('forged', 'project-1', 'compiled', '{}', 1, 'now', 'now')"
            )
            connection.commit()
        finally:
            connection.close()
        target = self.root / "restored.db"
        with self.assertRaises(IntegrityError):
            restore_backup(backup, target_database=target)
        self.assertFalse(target.exists())


class OperatorSnapshotTests(unittest.TestCase):
    def test_snapshot_is_redacted_and_does_not_initialize_missing_database(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "runtime.db"
            with self.assertRaisesRegex(IntegrityError, "existing runtime database"):
                operator_snapshot(database)
            self.assertFalse(database.exists())

            store = SQLiteStore(database)
            store.initialize()
            with store.transaction(immediate=True) as connection:
                store.append_event(
                    connection,
                    aggregate_type="operator_test",
                    aggregate_id="event-1",
                    expected_version=0,
                    project_id="project-1",
                    event_type="sensitive_payload_recorded",
                    actor="test-system",
                    command_id=str(uuid.uuid4()),
                    correlation_id="event-1",
                    policy_version="test-policy",
                    payload={"secret": "never-print-this-value"},
                )
            snapshot = operator_snapshot(database)
            serialized = json.dumps(snapshot)
            self.assertEqual(snapshot["event_log"]["count"], 1)
            self.assertTrue(snapshot["event_log"]["chain_verified"])
            self.assertNotIn("database_file", snapshot)
            self.assertRegex(snapshot["database_identity_digest"], r"^[0-9a-f]{64}$")
            self.assertNotIn(str(root), serialized)
            self.assertNotIn("never-print-this-value", serialized)
            self.assertNotIn("payload", serialized)
            self.assertIn(
                "production_readiness", snapshot["claim_boundary"]["non_claims"]
            )
            self.assertIn("pending_recovery", snapshot["outbox"])
            self.assertIn("unresolved", snapshot["integration"])
            self.assertIn("sealed_custody_attestations", snapshot["evaluation"])

    def test_snapshot_rejects_projection_rows_without_source_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "runtime.db"
            store = SQLiteStore(database)
            store.initialize()
            with store.transaction(immediate=True) as connection:
                connection.execute(
                    "INSERT INTO goals(goal_id, project_id, state, spec_json, "
                    "aggregate_version, created_at, updated_at) "
                    "VALUES ('goal-blocked', 'project-1', 'compiled', '{}', 1, "
                    "'now', 'now')"
                )
                connection.execute(
                    "INSERT INTO runs(run_id, goal_id, project_id, loop_state, "
                    "policy_version, aggregate_version, created_at, updated_at) "
                    "VALUES ('run-blocked', 'goal-blocked', 'project-1', "
                    "'blocked_with_decision', 'test-policy', 1, 'now', 'now')"
                )
            with self.assertRaises(IntegrityError):
                operator_snapshot(database)


class AdapterConformanceTests(unittest.TestCase):
    def test_bundled_fake_adapter_passes_reusable_conformance_harness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            adapter = FakeProvider(Path(temporary) / "provider.db")
            adapter.initialize()
            report = run_adapter_conformance(adapter, adapter_name="fake-provider")
            self.assertEqual(report.status, "passed")
            self.assertEqual(report.checks["request_digest_mismatch"], "rejected")
            self.assertIn("provider_exactly_once", report.non_claims)

    def test_fake_adapter_rejects_changed_request_before_idempotent_replay(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            adapter = FakeProvider(Path(temporary) / "provider.db")
            adapter.initialize()
            request = {"operation": "write"}
            from companyos_runtime.types import content_hash

            digest = content_hash(request)
            adapter.execute(
                project_id="project-1",
                idempotency_key="stable-key",
                effect_id="effect-1",
                request_digest=digest,
                request=request,
            )
            with self.assertRaisesRegex(IntegrityError, "request digest mismatch"):
                adapter.execute(
                    project_id="project-1",
                    idempotency_key="stable-key",
                    effect_id="effect-1",
                    request_digest=digest,
                    request={"operation": "changed"},
                )

    def test_conformance_rejects_adapter_crash_as_a_failed_contract(self) -> None:
        class CrashingMismatchAdapter(FakeProvider):
            def execute(self, **kwargs):
                request = kwargs["request"]
                if request.get("changed") is True:
                    raise RuntimeError("unexpected adapter crash")
                return super().execute(**kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            adapter = CrashingMismatchAdapter(Path(temporary) / "provider.db")
            adapter.initialize()
            with self.assertRaisesRegex(IntegrityError, "crashed instead of rejecting"):
                run_adapter_conformance(adapter, adapter_name="fake-provider")

    def test_conformance_requires_a_successful_baseline_effect(self) -> None:
        class FailedBaselineAdapter(FakeProvider):
            def execute(self, **kwargs):
                receipt = super().execute(**kwargs)
                return replace(receipt, status="failed")

        with tempfile.TemporaryDirectory() as temporary:
            adapter = FailedBaselineAdapter(Path(temporary) / "provider.db")
            adapter.initialize()
            with self.assertRaisesRegex(IntegrityError, "first execution receipt"):
                run_adapter_conformance(adapter, adapter_name="fake-provider")

    def test_conformance_requires_exact_declared_adapter_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            adapter = FakeProvider(Path(temporary) / "provider.db")
            adapter.initialize()
            with self.assertRaisesRegex(IntegrityError, "exactly match"):
                run_adapter_conformance(adapter, adapter_name="renamed-adapter")
            with self.assertRaises(AttributeError):
                adapter.adapter_id = "renamed-adapter"  # type: ignore[misc]


class ContinuousIntegrationContractTests(unittest.TestCase):
    def test_installers_copy_required_dotfile_contracts(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for installer in ("install.ps1", "install.sh"):
            with self.subTest(installer=installer):
                content = (root / installer).read_text(encoding="utf-8")
                self.assertIn(".gitattributes", content)

    def test_ci_covers_both_platforms_and_all_local_gates(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        for required in (
            "windows-latest",
            "ubuntu-latest",
            'python-version: ["3.11", "3.13"]',
            "ruff format --check .",
            "ruff check .",
            "mypy companyos_runtime",
            'python -B -m unittest discover -s tests -p "test_*.py" -v',
            "python -B -m companyos_runtime validate --repo .",
            "install.ps1",
            "install.sh",
            "contents: read",
        ):
            with self.subTest(required=required):
                self.assertIn(required, workflow)


if __name__ == "__main__":
    unittest.main()
