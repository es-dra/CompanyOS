from __future__ import annotations

import tempfile
import unittest
import uuid
from pathlib import Path

from companyos_runtime.evaluation import EvaluationRegistry
from companyos_runtime.evidence import EvidenceRegistry
from companyos_runtime.errors import (
    AuthorizationError,
    ContractError,
    EvidenceError,
    NotFoundError,
)
from companyos_runtime.memory import MemoryRegistry
from companyos_runtime.policy import PolicyEngine
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import (
    Capability,
    EvaluatorVerdict,
    EvidenceState,
    GoalSpec,
    TaskSpec,
    canonical_json,
    content_hash,
    utc_now,
)

from tests.evaluation_fixtures import (
    ExactTestEvalVerifier,
    make_eval_attestation,
)
from tests.identity_fixtures import IdentityFixture


class MemoryRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        self.store.initialize()
        self.identities = IdentityFixture(self.store)
        self.worker = self.identities.worker
        self.evaluator = self.identities.evaluator
        self._seed_execution()
        self.evidence = EvidenceRegistry(self.store)
        self.memory = MemoryRegistry(self.store)
        self.policy = PolicyEngine(self.store)
        self.evaluations = EvaluationRegistry(
            self.store, result_verifier=ExactTestEvalVerifier()
        )
        self.evidence_id = self._record_evidence("evidence-1", "internal")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _seed_execution(self) -> None:
        now = utc_now()
        promotion_capabilities = (
            Capability.DURABLE_MEMORY_PROMOTION,
            Capability.ACTIVE_RULE_PROMOTION,
        )
        goal_spec = GoalSpec(
            goal_id="goal-1",
            target_outcome="Verify evidence-backed memory promotion gates.",
            success_evidence_states=(EvidenceState.STRUCTURE,),
            allowed_capabilities=promotion_capabilities,
            write_scope=("engineering", "memory://memory-1"),
        )
        task_spec = TaskSpec(
            task_id="task-1",
            goal_id="goal-1",
            objective="Exercise memory promotion and wrong-capability rejection.",
            expected_delta="quality",
            primary_surface="memory://memory-1",
            evidence_target=EvidenceState.STRUCTURE,
            capabilities=promotion_capabilities,
            write_scope=("engineering", "memory://memory-1"),
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

    def _record_evidence(self, evidence_id: str, confidentiality: str) -> str:
        artifact = self.evidence.register_artifact(
            task_id="task-1",
            kind="test_report",
            uri=f"artifact://{evidence_id}",
            content_digest=content_hash({"evidence": evidence_id}),
            producer_session=self.worker,
            confidentiality=confidentiality,
            artifact_id=f"artifact-{evidence_id}",
        )
        claim = self.evidence.record_claim(
            task_id="task-1",
            claim=f"verified {evidence_id}",
            evidence_state=EvidenceState.STRUCTURE,
            artifact_refs=[artifact.artifact_id],
            verifier_session=self.identities.system,
            verifier_version="1",
            environment="local",
            evaluator_verdict=EvaluatorVerdict.NOT_REQUIRED,
            non_claims=["does not prove human acceptance"],
            evidence_id=evidence_id,
        )
        return claim.evidence_id

    def _record_eval(
        self,
        candidate_digest: str,
        *,
        dataset_split: str = "held_out",
        status: str = "pass",
        safety_failures: list[str] | None = None,
    ) -> str:
        eval_id = str(uuid.uuid4())
        dataset_digest = content_hash({"dataset": dataset_split, "eval_id": eval_id})
        metrics = {"pass_rate": 1.0}
        failures = tuple(safety_failures or ())
        attestation = make_eval_attestation(
            eval_id=eval_id,
            project_id="project-1",
            candidate_digest=candidate_digest,
            dataset_name="memory-regression",
            dataset_split=dataset_split,
            dataset_digest=dataset_digest,
            evaluator=self.evaluator,
            evaluator_version="1",
            status=status,
            metrics=metrics,
            safety_failures=failures,
        )
        recorded = self.evaluations.record_eval(
            project_id="project-1",
            candidate_digest=candidate_digest,
            dataset_name="memory-regression",
            dataset_split=dataset_split,
            dataset_digest=dataset_digest,
            evaluator=self.evaluator,
            evaluator_version="1",
            status=status,
            metrics=metrics,
            safety_failures=failures,
            eval_id=eval_id,
            attestation=attestation,
        )
        return recorded.eval_id

    def _approve(
        self,
        request: dict,
        *,
        capability: Capability = Capability.DURABLE_MEMORY_PROMOTION,
    ):
        return self.policy.record_approval(
            project_id="project-1",
            goal_id="goal-1",
            run_id="run-1",
            task_id="task-1",
            requester=self.worker,
            approver=self.identities.owner,
            capability=capability,
            action=request["action"],
            resource=request["resource"],
            request_digest=request["request_digest"],
            policy_version="policy-v1",
            decision="approved",
            ttl_seconds=600,
        )

    def _candidate(self, memory_id: str = "memory-1") -> dict:
        return self.memory.create_candidate(
            memory_id=memory_id,
            project_id="project-1",
            source_evidence_id=self.evidence_id,
            scope="engineering",
            classification="internal",
            content="Prefer the verified recovery path.",
            ttl_seconds=3600,
            actor=self.worker,
        )

    def test_candidate_requires_existing_evidence_and_preserves_provenance_ttl_and_classification(
        self,
    ) -> None:
        with self.assertRaises(NotFoundError):
            self.memory.create_candidate(
                memory_id="missing-evidence",
                project_id="project-1",
                source_evidence_id="does-not-exist",
                scope="engineering",
                classification="internal",
                content="unproven memory",
                actor=self.worker,
            )

        candidate = self._candidate()
        self.assertEqual(candidate["status"], "candidate")
        self.assertEqual(candidate["source_evidence_id"], self.evidence_id)
        self.assertEqual(candidate["scope"], "engineering")
        self.assertEqual(candidate["classification"], "internal")
        self.assertGreater(candidate["expires_at"], candidate["effective_at"])
        self.assertEqual(len(candidate["source_digest"]), 64)
        self.assertEqual(len(candidate["candidate_digest"]), 64)

        secret_evidence = self._record_evidence("evidence-secret", "secret")
        with self.assertRaises(ContractError):
            self.memory.create_candidate(
                memory_id="under-classified",
                project_id="project-1",
                source_evidence_id=secret_evidence,
                scope="engineering",
                classification="internal",
                content="secret-derived memory",
                actor=self.worker,
            )

    def test_promotion_requires_exact_human_approval_and_matching_passing_heldout_eval(
        self,
    ) -> None:
        candidate = self._candidate()
        limited_request = self.memory.promotion_request("memory-1", "limited")
        self.assertEqual(
            limited_request["candidate_digest"], candidate["candidate_digest"]
        )
        heldout = self._record_eval(candidate["candidate_digest"])
        approval = self._approve(limited_request)
        limited = self.memory.promote(
            memory_id="memory-1",
            target_status="limited",
            approval_id=approval.approval_id,
            heldout_eval_id=heldout,
            human_approver=self.identities.owner,
        )
        self.assertEqual(limited["status"], "limited")
        self.assertEqual(limited["candidate_digest"], candidate["candidate_digest"])

        active_request = self.memory.promotion_request("memory-1", "active")
        active_eval = self._record_eval(candidate["candidate_digest"])
        active_approval = self._approve(active_request)
        active = self.memory.promote(
            memory_id="memory-1",
            target_status="active",
            approval_id=active_approval.approval_id,
            heldout_eval_id=active_eval,
            human_approver=self.identities.owner,
        )
        self.assertEqual(active["status"], "active")
        self.assertEqual(
            self.store.query("SELECT COUNT(*) AS count FROM improvement_proposals")[0][
                "count"
            ],
            0,
        )

    def test_rule_approval_held_in_eval_and_direct_active_jump_are_rejected(
        self,
    ) -> None:
        candidate = self._candidate()
        with self.assertRaises(ContractError):
            self.memory.promotion_request("memory-1", "active")

        request = self.memory.promotion_request("memory-1", "limited")
        heldout = self._record_eval(candidate["candidate_digest"])
        rule_approval = self._approve(request)
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE approvals SET capability = ? WHERE approval_id = ?",
                (
                    Capability.ACTIVE_RULE_PROMOTION.value,
                    rule_approval.approval_id,
                ),
            )
        with self.assertRaises(AuthorizationError):
            self.memory.promote(
                memory_id="memory-1",
                target_status="limited",
                approval_id=rule_approval.approval_id,
                heldout_eval_id=heldout,
                human_approver=self.identities.owner,
            )

        valid_approval = self._approve(request)
        held_in = self._record_eval(
            candidate["candidate_digest"], dataset_split="held_in"
        )
        with self.assertRaises(AuthorizationError):
            self.memory.promote(
                memory_id="memory-1",
                target_status="limited",
                approval_id=valid_approval.approval_id,
                heldout_eval_id=heldout,
                human_approver="owner-without-human-principal",  # type: ignore[arg-type]
            )
        with self.assertRaises(EvidenceError):
            self.memory.promote(
                memory_id="memory-1",
                target_status="limited",
                approval_id=valid_approval.approval_id,
                heldout_eval_id=held_in,
                human_approver=self.identities.owner,
            )

    def test_promotion_rejects_provenance_changed_after_candidate_creation(
        self,
    ) -> None:
        candidate = self._candidate()
        request = self.memory.promotion_request("memory-1", "limited")
        heldout = self._record_eval(candidate["candidate_digest"])
        approval = self._approve(request)
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE artifacts SET content_digest = ? WHERE artifact_id = ?",
                (content_hash({"tampered": True}), "artifact-evidence-1"),
            )
        with self.assertRaisesRegex(EvidenceError, "provenance changed"):
            self.memory.promote(
                memory_id="memory-1",
                target_status="limited",
                approval_id=approval.approval_id,
                heldout_eval_id=heldout,
                human_approver=self.identities.owner,
            )


if __name__ == "__main__":
    unittest.main()
