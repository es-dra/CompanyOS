from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from companyos_runtime.context import ContextRegistry, TrustedSourceAttestation
from companyos_runtime.errors import AuthorizationError, ContractError
from companyos_runtime.scope import normalize_scope
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import (
    EvidenceState,
    GoalSpec,
    TaskSpec,
    canonical_json,
    content_hash,
    utc_now,
)


class _TestTrustedSourceVerifier:
    def verify(self, attestation: TrustedSourceAttestation) -> None:
        if attestation.proof != f"test-proof:{attestation.attestation_id}":
            raise AuthorizationError("invalid test attestation proof")


class _BooleanTrustedSourceVerifier:
    def verify(self, attestation: TrustedSourceAttestation) -> bool:
        del attestation
        return True


class ContextRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        self.store.initialize()
        self._seed_execution()
        self.context = ContextRegistry(
            self.store, trusted_source_verifier=_TestTrustedSourceVerifier()
        )
        self.now = datetime.now(UTC)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _seed_execution(self) -> None:
        now = utc_now()
        goal_spec = GoalSpec(
            goal_id="goal-1",
            target_outcome="assemble bounded context",
            success_evidence_states=(EvidenceState.STRUCTURE,),
            read_scope=("engineering",),
        )
        task_spec = TaskSpec(
            task_id="task-1",
            goal_id="goal-1",
            objective="assemble bounded context",
            expected_delta="quality",
            primary_surface="engineering",
            evidence_target=EvidenceState.STRUCTURE,
            read_scope=("engineering",),
            integration_required=False,
        )
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "INSERT INTO goals VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "goal-1",
                    "project-1",
                    "ready",
                    canonical_json(goal_spec.to_dict()),
                    1,
                    now,
                    now,
                ),
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
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)
                """,
                (
                    "task-1",
                    "goal-1",
                    "run-1",
                    "project-1",
                    "ready",
                    canonical_json(task_spec.to_dict()),
                    1,
                    now,
                    now,
                ),
            )

    @staticmethod
    def _iso(value: str | datetime | None) -> str | None:
        if value is None:
            return None
        parsed = (
            datetime.fromisoformat(value.replace("Z", "+00:00"))
            if isinstance(value, str)
            else value
        )
        return parsed.astimezone(UTC).isoformat(timespec="microseconds")

    def _values(self, context_id: str, **overrides):
        values = {
            "context_id": context_id,
            "project_id": "project-1",
            "scope": "engineering",
            "source_ref": f"source://{context_id}",
            "content": f"instruction {context_id}",
            "classification": "internal",
            "normative_status": "active",
            "priority": 10,
            "token_estimate": 2,
            "observed_at": self.now,
            "effective_at": self.now,
        }
        values.update(overrides)
        return values

    def _trusted_import_args(self, context_id: str, **overrides):
        values = self._values(context_id, **overrides)
        policy_version = values.pop("policy_version", "policy-v1")
        attestation_id = f"attestation:{context_id}"
        attestation = TrustedSourceAttestation(
            attestation_id=attestation_id,
            proof=f"test-proof:{attestation_id}",
            context_id=values["context_id"],
            project_id=values["project_id"],
            scope=normalize_scope(values["scope"]),
            source_ref=values["source_ref"],
            source_digest=content_hash(
                {
                    "source_ref": values["source_ref"],
                    "content": values["content"],
                }
            ),
            classification=values["classification"],
            normative_status=values["normative_status"],
            priority=values["priority"],
            token_estimate=values["token_estimate"],
            observed_at=self._iso(values["observed_at"]),
            effective_at=self._iso(values["effective_at"]),
            expires_at=self._iso(values.get("expires_at")),
            supersedes=values.get("supersedes"),
            policy_version=policy_version,
        )
        return {
            **values,
            "policy_version": policy_version,
            "attestation": attestation,
        }

    def _register(self, context_id: str, **overrides):
        values = self._values(context_id, **overrides)
        if values["normative_status"] in {"active", "limited"}:
            return self.context.import_trusted(
                **self._trusted_import_args(context_id, **overrides)
            )
        return self.context.register(**values)

    def _inject_untrusted_normative(self, context_id: str, **overrides) -> None:
        values = self._values(context_id, **overrides)
        observed = self._iso(values["observed_at"])
        effective = self._iso(values["effective_at"])
        expires = self._iso(values.get("expires_at"))
        source_digest = content_hash(
            {"source_ref": values["source_ref"], "content": values["content"]}
        )
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO context_items(
                    context_id, project_id, scope, source_ref, source_digest,
                    content, classification, normative_status, priority,
                    token_estimate, observed_at, effective_at, expires_at,
                    supersedes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    values["context_id"],
                    values["project_id"],
                    normalize_scope(values["scope"]),
                    values["source_ref"],
                    source_digest,
                    values["content"],
                    values["classification"],
                    values["normative_status"],
                    values["priority"],
                    values["token_estimate"],
                    observed,
                    effective,
                    expires,
                    values.get("supersedes"),
                    utc_now(),
                ),
            )

    def test_register_rejects_normative_and_lifecycle_state_injection(self) -> None:
        for index, status in enumerate(
            ("active", "limited", "historical_draft", "rejected", "retired")
        ):
            with self.subTest(status=status), self.assertRaises(AuthorizationError):
                self.context.register(
                    **self._values(f"injected-{index}", normative_status=status),
                    actor="owner",
                    policy_version="identity-authority",
                )

        self.assertEqual(
            self.store.query(
                "SELECT COUNT(*) AS count FROM context_items WHERE context_id LIKE ?",
                ("injected-%",),
            )[0]["count"],
            0,
        )

    def test_trusted_import_is_fail_closed_and_rejects_caller_flags(self) -> None:
        deny_all = ContextRegistry(self.store)
        denied_args = self._trusted_import_args("deny-all")
        with self.assertRaises(AuthorizationError):
            deny_all.import_trusted(**denied_args)

        boolean_args = self._trusted_import_args("boolean-attestation")
        boolean_args["attestation"] = True
        with self.assertRaises(ContractError):
            self.context.import_trusted(**boolean_args)

        boolean_verifier = ContextRegistry(
            self.store,
            trusted_source_verifier=_BooleanTrustedSourceVerifier(),
        )
        with self.assertRaises(AuthorizationError):
            boolean_verifier.import_trusted(
                **self._trusted_import_args("boolean-verifier")
            )

    def test_trusted_import_requires_exact_digest_policy_and_verified_proof(
        self,
    ) -> None:
        digest_args = self._trusted_import_args("digest-mismatch")
        digest_args["attestation"] = replace(
            digest_args["attestation"], source_digest="0" * 64
        )
        with self.assertRaises(AuthorizationError):
            self.context.import_trusted(**digest_args)

        policy_args = self._trusted_import_args("policy-mismatch")
        policy_args["policy_version"] = "policy-v2"
        with self.assertRaises(AuthorizationError):
            self.context.import_trusted(**policy_args)

        proof_args = self._trusted_import_args("proof-mismatch")
        proof_args["attestation"] = replace(
            proof_args["attestation"], proof="forged-proof"
        )
        with self.assertRaises(AuthorizationError):
            self.context.import_trusted(**proof_args)

        self.assertEqual(
            self.store.query(
                "SELECT COUNT(*) AS count FROM context_items WHERE context_id LIKE ?",
                ("%-mismatch",),
            )[0]["count"],
            0,
        )

    def test_assembly_rejects_direct_active_injection_and_ignores_its_supersession(
        self,
    ) -> None:
        self._register("trusted-old", priority=10)
        self._inject_untrusted_normative(
            "forged-successor", priority=100, supersedes="trusted-old"
        )

        result = self.context.assemble(
            assembly_id="assembly-forged-successor",
            project_id="project-1",
            run_id="run-1",
            task_id="task-1",
            scopes=["engineering"],
            token_budget=20,
            as_of=self.now,
        )

        self.assertEqual(
            [item["context_id"] for item in result["selected"]], ["trusted-old"]
        )
        rejected = {item["context_id"]: item["reason"] for item in result["rejected"]}
        self.assertEqual(rejected["forged-successor"], "untrusted_normative_source")

    def test_assembly_rejects_normative_content_tampered_after_import(self) -> None:
        self._register("tampered-active")
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE context_items SET content = ? WHERE context_id = ?",
                ("injected replacement", "tampered-active"),
            )

        result = self.context.assemble(
            assembly_id="assembly-tampered-content",
            project_id="project-1",
            run_id="run-1",
            task_id="task-1",
            scopes=["engineering"],
            token_budget=20,
            as_of=self.now,
        )

        self.assertEqual(result["selected"], [])
        rejected = {item["context_id"]: item["reason"] for item in result["rejected"]}
        self.assertEqual(rejected["tampered-active"], "source_digest_mismatch")

    def test_assembly_excludes_candidate_expired_private_future_and_out_of_scope_items(
        self,
    ) -> None:
        self._register("active")
        self._register("limited", normative_status="limited", priority=9)
        self._register("candidate", normative_status="candidate", priority=100)
        self._register(
            "expired",
            effective_at=self.now - timedelta(days=2),
            expires_at=self.now - timedelta(days=1),
        )
        self._register("private", classification="private")
        self._register("other-scope", scope="strategy")
        self._register("future", effective_at=self.now + timedelta(days=1))
        self._register("foreign-project", project_id="project-2")

        result = self.context.assemble(
            assembly_id="assembly-1",
            project_id="project-1",
            run_id="run-1",
            task_id="task-1",
            scopes=["engineering"],
            token_budget=20,
            as_of=self.now,
        )

        self.assertEqual(
            [item["context_id"] for item in result["selected"]], ["active", "limited"]
        )
        rejected = {item["context_id"]: item["reason"] for item in result["rejected"]}
        self.assertEqual(rejected["candidate"], "normative_status:candidate")
        self.assertEqual(rejected["expired"], "expired")
        self.assertEqual(rejected["private"], "private_classification")
        self.assertEqual(rejected["other-scope"], "out_of_scope")
        self.assertEqual(rejected["future"], "not_effective")
        self.assertNotIn("foreign-project", rejected)
        self.assertEqual(result["used_tokens"], 4)

        persisted = self.context.get_assembly("assembly-1")
        self.assertEqual(persisted["assembly_digest"], result["assembly_digest"])
        selected_json = self.store.query(
            "SELECT selected_json FROM context_assemblies WHERE assembly_id = ?",
            ("assembly-1",),
        )[0]["selected_json"]
        self.assertNotIn("instruction candidate", selected_json)
        self.assertNotIn("instruction private", selected_json)

    def test_only_effective_promoted_successor_suppresses_an_active_item(self) -> None:
        old = self._register("old", source_ref="source://policy", content="old policy")
        self._register(
            "candidate-successor",
            source_ref="source://policy-v2",
            content="candidate policy",
            normative_status="candidate",
            supersedes="old",
            priority=30,
        )
        first = self.context.assemble(
            assembly_id="assembly-before-promotion",
            project_id="project-1",
            run_id="run-1",
            task_id="task-1",
            scopes=["engineering"],
            token_budget=10,
            as_of=self.now,
        )
        self.assertIn("old", {item["context_id"] for item in first["selected"]})
        self.assertEqual(
            old["source_digest"],
            content_hash({"source_ref": "source://policy", "content": "old policy"}),
        )

        self._register(
            "active-successor",
            source_ref="source://policy-v3",
            content="active replacement",
            normative_status="active",
            supersedes="old",
            priority=40,
        )
        second = self.context.assemble(
            assembly_id="assembly-after-promotion",
            project_id="project-1",
            run_id="run-1",
            task_id="task-1",
            scopes=["engineering"],
            token_budget=10,
            as_of=self.now,
        )
        self.assertIn(
            "active-successor", {item["context_id"] for item in second["selected"]}
        )
        rejected = {item["context_id"]: item["reason"] for item in second["rejected"]}
        self.assertEqual(rejected["old"], "superseded_by:active-successor")

    def test_token_budget_rejection_does_not_block_a_smaller_later_item(self) -> None:
        self._register("large", priority=100, token_estimate=8)
        self._register("small", priority=10, token_estimate=3)
        result = self.context.assemble(
            assembly_id="assembly-budget",
            project_id="project-1",
            run_id="run-1",
            task_id="task-1",
            scopes=["engineering"],
            token_budget=4,
        )
        self.assertEqual([item["context_id"] for item in result["selected"]], ["small"])
        self.assertEqual(
            {item["context_id"]: item["reason"] for item in result["rejected"]}[
                "large"
            ],
            "token_budget",
        )

        deny_all = self.context.assemble(
            assembly_id="assembly-no-classifications",
            project_id="project-1",
            run_id="run-1",
            task_id="task-1",
            scopes=["engineering"],
            token_budget=20,
            allowed_classifications=[],
        )
        self.assertEqual(deny_all["selected"], [])


if __name__ == "__main__":
    unittest.main()
