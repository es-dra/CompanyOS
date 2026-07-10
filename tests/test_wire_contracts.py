from __future__ import annotations

import json
import unittest
from dataclasses import fields
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from companyos_runtime.leases import LeaseOperationResult, LeaseRecord
from companyos_runtime.workflow import (
    EffectReceipt,
    EnqueueEffectResult,
    OutboxEffect,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


class WireContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(
            (
                REPO_ROOT / "runtime/contracts/v1/runtime-contracts.schema.json"
            ).read_text(encoding="utf-8")
        )

    def _validate(self, definition: str, instance: dict[str, Any]) -> None:
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": f"#/$defs/{definition}",
            "$defs": self.contract["$defs"],
        }
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(instance)

    def test_lease_wire_excludes_operation_replay_metadata(self) -> None:
        result = LeaseOperationResult(
            resource_key="repo://project/worktree",
            project_id="project-1",
            task_id="task-1",
            holder="worker-1",
            fence=1,
            issued_at="2026-01-01T00:00:00Z",
            expires_at="2026-01-01T00:05:00Z",
            replayed=True,
        )

        wire = result.to_wire()

        self.assertNotIn("replayed", wire)
        self.assertEqual(
            set(wire),
            {item.name for item in fields(LeaseRecord)},
        )
        self._validate("Lease", wire)

    def test_outbox_wire_includes_persisted_schema_fields_only(self) -> None:
        result = EnqueueEffectResult(
            effect_id="effect-1",
            project_id="project-1",
            run_id="run-1",
            task_id="task-1",
            step_id="step-1",
            adapter="fake-provider",
            idempotency_key="effect-key-1",
            request_digest="0" * 64,
            status="authorization_pending",
            created_at="2026-01-01T00:00:00Z",
            replayed=True,
        )

        wire = result.to_wire()

        self.assertNotIn("replayed", wire)
        self.assertEqual(
            set(wire),
            {item.name for item in fields(OutboxEffect)},
        )
        self.assertIsNone(wire["dispatched_at"])
        self.assertIsNone(wire["reconciled_at"])
        self.assertIsNone(wire["last_error"])
        self._validate("OutboxEffect", wire)

    def test_effect_receipt_wire_copies_result_and_matches_schema(self) -> None:
        result = {"accepted": True}
        receipt = EffectReceipt(
            receipt_id="receipt-1",
            effect_id="effect-1",
            status="succeeded",
            provider_receipt=None,
            result=result,
            result_digest="1" * 64,
            recorded_at="2026-01-01T00:01:00Z",
        )

        wire = receipt.to_wire()

        self.assertEqual(
            set(wire),
            {item.name for item in fields(EffectReceipt)},
        )
        self.assertIsNot(wire["result"], result)
        self._validate("EffectReceipt", wire)


if __name__ == "__main__":
    unittest.main()
