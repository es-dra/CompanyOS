from __future__ import annotations

import builtins
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from companyos_runtime.errors import ContractError
from companyos_runtime.types import Capability, EvidenceState, IntegrationState
from companyos_runtime.validation import (
    REQUIRED_FILES,
    STRUCTURE_VALIDATION_NON_CLAIMS,
    _load_jsonschema,
    validate_repository,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


class RepositoryValidationTests(unittest.TestCase):
    def _copy_validation_surface(self, destination: Path) -> None:
        for relative_name in REQUIRED_FILES:
            source = REPO_ROOT / relative_name
            target = destination / relative_name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    def test_repository_validation_runs_draft_2020_12_instances(self) -> None:
        result = validate_repository(REPO_ROOT)

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["evidence_state"], "structure_verification")
        self.assertGreaterEqual(result["draft_2020_12_schemas_checked"], 5)
        self.assertEqual(result["instances_validated"], 15)
        self.assertEqual(
            set(result["non_claims"]), set(STRUCTURE_VALIDATION_NON_CLAIMS)
        )

    def test_schema_enums_match_runtime_enums(self) -> None:
        contract = json.loads(
            (
                REPO_ROOT / "runtime/contracts/v1/runtime-contracts.schema.json"
            ).read_text(encoding="utf-8")
        )
        run_log = json.loads(
            (REPO_ROOT / "runtime/run-log.schema.json").read_text(encoding="utf-8")
        )

        self.assertEqual(
            set(contract["$defs"]["Capability"]["enum"]),
            {item.value for item in Capability},
        )
        self.assertEqual(
            set(contract["$defs"]["EvidenceState"]["enum"]),
            {item.value for item in EvidenceState},
        )
        self.assertEqual(
            set(run_log["properties"]["integration_queue_state"]["enum"]),
            {"none", *(item.value for item in IntegrationState)},
        )

    def test_compiled_instance_is_validated_not_only_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            self._copy_validation_surface(root)
            contract_path = root / "runtime/contracts/v1/runtime-contracts.schema.json"
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            contract["$defs"]["GoalSpec"]["properties"]["goal_id"] = {
                "const": "a-different-goal"
            }
            contract_path.write_text(
                json.dumps(contract, indent=2) + "\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(
                ContractError, "instance validation failed for compiled GoalSpec"
            ):
                validate_repository(root)

    def test_enum_parity_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            self._copy_validation_surface(root)
            contract_path = root / "runtime/contracts/v1/runtime-contracts.schema.json"
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            contract["$defs"]["Capability"]["enum"].remove("network")
            contract_path.write_text(
                json.dumps(contract, indent=2) + "\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(
                ContractError, "Capability enum parity mismatch"
            ):
                validate_repository(root)

    def test_wire_dto_parity_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            self._copy_validation_surface(root)
            contract_path = root / "runtime/contracts/v1/runtime-contracts.schema.json"
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            del contract["$defs"]["OutboxEffect"]["properties"]["last_error"]
            contract_path.write_text(
                json.dumps(contract, indent=2) + "\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(
                ContractError, "OutboxEffect wire property parity mismatch"
            ):
                validate_repository(root)

    def test_active_rule_record_schema_parity_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            self._copy_validation_surface(root)
            contract_path = root / "runtime/contracts/v1/runtime-contracts.schema.json"
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            del contract["$defs"]["ActiveRulePromotionRecord"]["properties"][
                "sealed_attestation_digest"
            ]
            contract_path.write_text(
                json.dumps(contract, indent=2) + "\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(
                ContractError, "ActiveRulePromotionRecord property parity mismatch"
            ):
                validate_repository(root)

    def test_authoring_compatibility_artifact_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            self._copy_validation_surface(root)
            compiler_path = root / "companyos_runtime/compiler.py"
            compiler_path.write_text(
                compiler_path.read_text(encoding="utf-8") + "\n# drift\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ContractError, "compatibility artifact digest drifted: compiler"
            ):
                validate_repository(root)

    def test_authoring_compatibility_digests_are_eol_portable(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            self._copy_validation_surface(root)
            template = root / "templates/GOAL_CONTRACT.md"
            content = template.read_text(encoding="utf-8").replace("\n", "\r\n")
            template.write_bytes(content.encode("utf-8"))

            result = validate_repository(root)
            self.assertEqual(result["status"], "passed")

    def test_package_version_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            root = Path(raw_temp)
            self._copy_validation_surface(root)
            (root / "VERSION").write_text("9.9.9\n", encoding="utf-8")

            with self.assertRaisesRegex(ContractError, "package version drifted"):
                validate_repository(root)

    def test_missing_jsonschema_dependency_has_actionable_error(self) -> None:
        real_import = builtins.__import__

        def import_without_jsonschema(
            name: str,
            globals: dict[str, object] | None = None,
            locals: dict[str, object] | None = None,
            fromlist: tuple[str, ...] = (),
            level: int = 0,
        ) -> object:
            if name == "jsonschema" or name.startswith("jsonschema."):
                raise ImportError("dependency intentionally unavailable")
            return real_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=import_without_jsonschema):
            with self.assertRaisesRegex(ContractError, "jsonschema>=4.18"):
                _load_jsonschema()


if __name__ == "__main__":
    unittest.main()
