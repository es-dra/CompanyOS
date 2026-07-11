"""Real-subprocess CLI tests with Python network access forcibly disabled."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


_NETWORK_GUARDED_ENTRYPOINT = r"""
import socket
import sys

def denied(*args, **kwargs):
    raise RuntimeError("network access is disabled by the CLI evaluator")

class GuardedSocket(socket.socket):
    def connect(self, *args, **kwargs):
        return denied(*args, **kwargs)

    def connect_ex(self, *args, **kwargs):
        return denied(*args, **kwargs)

socket.socket = GuardedSocket
socket.create_connection = denied

from companyos_runtime.cli import main
raise SystemExit(main(sys.argv[1:]))
"""


class CLISubprocessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(__file__).resolve().parents[1]
        self.state_dir = Path(self.temp.name) / "state"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        secret_markers = (
            "API_KEY",
            "ACCESS_KEY",
            "SECRET_KEY",
            "AUTH_TOKEN",
            "BEARER_TOKEN",
            "OPENAI",
            "ANTHROPIC",
            "DEEPSEEK",
            "KLING",
        )
        for name in tuple(environment):
            if any(marker in name.upper() for marker in secret_markers):
                environment.pop(name, None)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(self.root)
        return environment

    def _run(self, *arguments: str) -> dict:
        completed = subprocess.run(
            [sys.executable, "-B", "-c", _NETWORK_GUARDED_ENTRYPOINT, *arguments],
            cwd=self.root,
            env=self._environment(),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(completed.stderr.strip(), completed.stderr)
        return json.loads(completed.stdout)

    def test_validate_runs_in_a_network_disabled_subprocess(self) -> None:
        result = self._run("validate", "--repo", str(self.root))
        self.assertEqual(result["status"], "passed")
        self.assertGreaterEqual(result["required_files"], 1)
        self.assertGreaterEqual(result["contract_definitions"], 10)
        self.assertIn("provider_smoke", result["non_claims"])

    def test_demo_and_verify_run_in_real_subprocesses_with_zero_provider_cost(
        self,
    ) -> None:
        demo = self._run(
            "demo",
            "--state-dir",
            str(self.state_dir),
            "--fault-at",
            "after_effect_before_checkpoint",
        )
        self.assertTrue(demo["simulated_crash_observed"])
        self.assertEqual(demo["run_state"], "delivered")
        self.assertEqual(demo["task_state"], "delivered")
        self.assertEqual(demo["effect_status"], "succeeded")
        self.assertEqual(demo["external_effect_delta"], 1)
        self.assertEqual(demo["provider_cost"], 0.0)
        self.assertEqual(demo["evidence_state"], "runtime_verification")
        self.assertIn("provider_smoke", demo["non_claims"])
        self.assertIn("active_rule_promotion", demo["non_claims"])

        verified = self._run("--db", str(self.state_dir / "runtime.db"), "verify")
        self.assertEqual(verified["status"], "passed")
        self.assertGreater(verified["event_chain_length"], 0)
        self.assertEqual(
            verified["core_projections"],
            {"goals": 1, "runs": 1, "tasks": 1},
        )

    def test_backup_restore_operator_and_adapter_conformance_are_offline(self) -> None:
        database = self.state_dir / "runtime.db"
        backup = self.state_dir / "backup.db"
        restored = self.state_dir / "restored.db"
        initialized = self._run("--db", str(database), "init")
        self.assertEqual(initialized["status"], "initialized")

        backup_result = self._run(
            "--db", str(database), "backup", "--target", str(backup)
        )
        self.assertEqual(backup_result["verification"]["event_chain"], "passed")
        self.assertFalse(backup_result["recovery_set"]["complete"])

        restore_result = self._run(
            "restore", "--backup", str(backup), "--target", str(restored)
        )
        self.assertEqual(restore_result["status"], "restored_verified")
        snapshot = self._run("--db", str(restored), "operator-snapshot")
        self.assertTrue(snapshot["event_log"]["chain_verified"])
        self.assertNotIn("database_file", snapshot)
        self.assertRegex(snapshot["database_identity_digest"], r"^[0-9a-f]{64}$")

        conformance = self._run(
            "adapter-conformance",
            "--state-dir",
            str(self.state_dir / "conformance"),
        )
        self.assertEqual(conformance["status"], "passed")
        self.assertIn("provider_exactly_once", conformance["non_claims"])


if __name__ == "__main__":
    unittest.main()
