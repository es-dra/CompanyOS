"""Independent evaluator tests for authenticated evidence provenance."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from companyos_runtime.errors import AuthorizationError, EvidenceError, IntegrityError
from companyos_runtime.evidence import EvidenceRegistry
from companyos_runtime.identity import IdentityManager, Role, VerifiedPrincipal
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import (
    EvidenceState,
    EvaluatorVerdict,
    GoalSpec,
    TaskSpec,
    canonical_json,
    content_hash,
    utc_now,
)


class EvidenceRegistryTests(unittest.TestCase):
    OWNER_CREDENTIAL = "owner-evidence-credential"
    MAKER_CREDENTIAL = "maker-evidence-credential"
    VERIFIER_CREDENTIAL = "verifier-evidence-credential"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        self.store.initialize()
        self.identities = IdentityManager(self.store)
        self.owner_session = self.identities.bootstrap_owner(
            display_name="Evidence Owner",
            credential=self.OWNER_CREDENTIAL,
        )
        self.identities.set_roles(
            self.owner_session,
            display_name="Evidence Owner",
            roles={Role.OWNER, Role.HUMAN_ACCEPTOR},
        )
        self._create_principal(
            display_name="Artifact Maker",
            credential=self.MAKER_CREDENTIAL,
            roles={
                Role.WORKER,
                Role.SYSTEM,
                Role.EVALUATOR,
                Role.PROVIDER_ATTESTOR,
                Role.HUMAN_ACCEPTOR,
                Role.BUSINESS_REVIEWER,
            },
        )
        self._create_principal(
            display_name="Independent Verifier",
            credential=self.VERIFIER_CREDENTIAL,
            roles={
                Role.EVALUATOR,
                Role.PROVIDER_ATTESTOR,
                Role.HUMAN_ACCEPTOR,
                Role.BUSINESS_REVIEWER,
            },
        )
        self.maker_session = self.identities.authenticate(
            display_name="Artifact Maker",
            credential=self.MAKER_CREDENTIAL,
        )
        self.verifier_session = self.identities.authenticate(
            display_name="Independent Verifier",
            credential=self.VERIFIER_CREDENTIAL,
        )
        self._seed_execution()
        # Exercise the required default identity-manager construction path.
        self.evidence = EvidenceRegistry(self.store)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _create_principal(
        self,
        *,
        display_name: str,
        credential: str,
        roles: set[Role],
    ) -> None:
        self.identities.create_principal(
            self.owner_session,
            display_name=display_name,
            credential=credential,
            roles=roles,
        )

    def test_terminal_task_is_sealed_against_new_artifacts_and_claims(self) -> None:
        prior = self.evidence.register_artifact(
            task_id="task-a",
            kind="test_report",
            uri="artifact://task-a/prior",
            content_digest=content_hash("prior evidence"),
            producer_session=self.maker_session,
        )
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE tasks SET state = 'canceled' WHERE task_id = 'task-a'"
            )
        with self.assertRaisesRegex(EvidenceError, "terminal task"):
            self.evidence.register_artifact(
                task_id="task-a",
                kind="test_report",
                uri="artifact://task-a/late",
                content_digest=content_hash("late evidence"),
                producer_session=self.maker_session,
            )
        with self.assertRaisesRegex(EvidenceError, "terminal task"):
            self.evidence.record_claim(
                task_id="task-a",
                claim="late claim must not reopen a canceled task",
                evidence_state=EvidenceState.RUNTIME,
                artifact_refs=(prior.artifact_id,),
                verifier_session=self.verifier_session,
                verifier_version="1",
                environment="local",
                evaluator_verdict=EvaluatorVerdict.PASS,
            )

    @staticmethod
    def _task(task_id: str, *, evaluator_required: bool = False) -> TaskSpec:
        return TaskSpec.from_dict(
            {
                "task_id": task_id,
                "goal_id": "goal-1",
                "objective": f"verify evidence for {task_id}",
                "expected_delta": "quality",
                "primary_surface": f"artifact://{task_id}",
                "evidence_target": "runtime_verification",
                "capabilities": ["read_local"],
                "read_scope": ["workspace://project/public"],
                "evaluator_required": evaluator_required,
            }
        )

    def _seed_execution(self) -> None:
        now = utc_now()
        goal = GoalSpec.from_dict(
            {
                "goal_id": "goal-1",
                "target_outcome": "verify evidence boundaries",
                "success_evidence_states": ["runtime_verification"],
                "read_scope": ["workspace://project/public/**"],
            }
        )
        tasks = (
            self._task("task-a"),
            self._task("task-b"),
            self._task("task-evaluator", evaluator_required=True),
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
            for task in tasks:
                connection.execute(
                    """
                    INSERT INTO tasks(
                        task_id, goal_id, run_id, project_id, state, spec_json,
                        aggregate_version, attempt_count, due_at,
                        last_error_fingerprint, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)
                    """,
                    (
                        task.task_id,
                        task.goal_id,
                        "run-1",
                        "project-1",
                        "ready",
                        canonical_json(task.to_dict()),
                        1,
                        now,
                        now,
                    ),
                )

    def _artifact(
        self,
        task_id: str,
        kind: str,
        label: str,
        *,
        producer_session: VerifiedPrincipal | None = None,
        artifact_id: str | None = None,
    ):
        return self.evidence.register_artifact(
            task_id=task_id,
            kind=kind,
            uri=f"artifact://{task_id}/{label}",
            content_digest=content_hash(f"{task_id}:{kind}:{label}"),
            producer_session=producer_session or self.maker_session,
            artifact_id=artifact_id,
        )

    def test_unauthenticated_and_string_identities_fail_closed(self) -> None:
        artifact_args = {
            "task_id": "task-a",
            "kind": "test_report",
            "uri": "artifact://task-a/untrusted",
            "content_digest": content_hash("untrusted"),
        }
        for forged_session in (None, "worker:forged"):
            with self.subTest(producer=forged_session):
                with self.assertRaisesRegex(
                    AuthorizationError, "authenticated session is required"
                ):
                    self.evidence.register_artifact(
                        **artifact_args,
                        producer_session=forged_session,  # type: ignore[arg-type]
                    )

        report = self._artifact("task-a", "test_report", "trusted")
        claim_args = {
            "task_id": "task-a",
            "claim": "a forged identity attempts to verify evidence",
            "evidence_state": EvidenceState.RUNTIME,
            "artifact_refs": [report.artifact_id],
            "verifier_version": "1",
            "environment": "local",
            "evaluator_verdict": EvaluatorVerdict.NOT_REQUIRED,
        }
        for forged_session in (None, "human:owner", "provider:fixture"):
            with self.subTest(verifier=forged_session):
                with self.assertRaisesRegex(
                    AuthorizationError, "authenticated session is required"
                ):
                    self.evidence.record_claim(
                        **claim_args,
                        verifier_session=forged_session,  # type: ignore[arg-type]
                    )

    def test_fake_runtime_is_allowed_but_fake_stronger_claims_are_rejected(
        self,
    ) -> None:
        runtime_artifact = self._artifact("task-a", "test_report", "runtime")
        runtime_claim = self.evidence.record_claim(
            task_id="task-a",
            claim="the deterministic fake workflow ran",
            evidence_state=EvidenceState.RUNTIME,
            artifact_refs=[runtime_artifact.artifact_id],
            verifier_session=self.maker_session,
            verifier_version="1",
            environment="fake",
            evaluator_verdict=EvaluatorVerdict.NOT_REQUIRED,
            non_claims=[
                "not provider smoke",
                "not human acceptance",
                "not business validation",
            ],
        )
        self.assertIs(runtime_claim.evidence_state, EvidenceState.RUNTIME)
        self.assertTrue(self.evidence.require_task_evidence("task-a").satisfied)

        cases = (
            (EvidenceState.PROVIDER_SMOKE, "provider_receipt"),
            (EvidenceState.HUMAN_ACCEPTANCE, "human_acceptance"),
            (EvidenceState.BUSINESS_VALIDATION, "business_validation"),
        )
        for state, kind in cases:
            artifact = self._artifact("task-a", kind, state.value)
            with self.subTest(state=state):
                with self.assertRaisesRegex(
                    EvidenceError, "can prove only structure/runtime"
                ):
                    self.evidence.record_claim(
                        task_id="task-a",
                        claim=f"fake environment claims {state.value}",
                        evidence_state=state,
                        artifact_refs=[artifact.artifact_id],
                        verifier_session=self.verifier_session,
                        verifier_version="1",
                        environment="fake",
                        evaluator_verdict=EvaluatorVerdict.PASS,
                    )

    def test_typed_artifacts_and_claims_enforce_corresponding_roles(self) -> None:
        with self.assertRaisesRegex(AuthorizationError, "provider_attestor"):
            self._artifact(
                "task-a",
                "provider_receipt",
                "owner-cannot-attest",
                producer_session=self.owner_session,
            )

        ordinary = self._artifact("task-a", "test_report", "ordinary")
        for state, required_kind in (
            (EvidenceState.PROVIDER_SMOKE, "provider_receipt"),
            (EvidenceState.HUMAN_ACCEPTANCE, "human_acceptance"),
            (EvidenceState.BUSINESS_VALIDATION, "business_validation"),
        ):
            with self.subTest(missing_kind=required_kind):
                with self.assertRaisesRegex(EvidenceError, required_kind):
                    self.evidence.record_claim(
                        task_id="task-a",
                        claim=f"unproven {state.value}",
                        evidence_state=state,
                        artifact_refs=[ordinary.artifact_id],
                        verifier_session=self.verifier_session,
                        verifier_version="1",
                        environment="controlled-live",
                        evaluator_verdict=EvaluatorVerdict.PASS,
                    )

        for state, kind in (
            (EvidenceState.PROVIDER_SMOKE, "provider_receipt"),
            (EvidenceState.HUMAN_ACCEPTANCE, "human_acceptance"),
            (EvidenceState.BUSINESS_VALIDATION, "business_validation"),
        ):
            artifact = self._artifact("task-a", kind, f"live-{kind}")
            with self.subTest(accepted=state):
                claim = self.evidence.record_claim(
                    task_id="task-a",
                    claim=f"scoped {state.value} evidence",
                    evidence_state=state,
                    artifact_refs=[artifact.artifact_id],
                    verifier_session=self.verifier_session,
                    verifier_version="1",
                    environment="controlled-live",
                    evaluator_verdict=EvaluatorVerdict.PASS,
                )
                self.assertIs(claim.evidence_state, state)
                self.assertEqual(
                    claim.verifier_principal_id,
                    self.verifier_session.principal_id,
                )

    def test_passing_evaluator_cannot_verify_own_artifact(self) -> None:
        report = self._artifact("task-a", "test_report", "maker-checker")
        for verdict in (
            EvaluatorVerdict.PASS,
            EvaluatorVerdict.PASS_WITH_RISK,
        ):
            with self.subTest(verdict=verdict):
                with self.assertRaisesRegex(
                    AuthorizationError, "independent evaluator"
                ):
                    self.evidence.record_claim(
                        task_id="task-a",
                        claim="the maker attempts to accept its own evidence",
                        evidence_state=EvidenceState.RUNTIME,
                        artifact_refs=[report.artifact_id],
                        verifier_session=self.maker_session,
                        verifier_version="1",
                        environment="local",
                        evaluator_verdict=verdict,
                    )

        accepted = self.evidence.record_claim(
            task_id="task-a",
            claim="a distinct evaluator accepted the evidence",
            evidence_state=EvidenceState.RUNTIME,
            artifact_refs=[report.artifact_id],
            verifier_session=self.verifier_session,
            verifier_version="1",
            environment="local",
            evaluator_verdict=EvaluatorVerdict.PASS,
        )
        self.assertEqual(accepted.verifier, self.verifier_session.principal_id)

    def test_artifact_from_another_task_cannot_support_a_claim(self) -> None:
        foreign = self._artifact("task-a", "test_report", "foreign")
        with self.assertRaisesRegex(EvidenceError, "same task"):
            self.evidence.record_claim(
                task_id="task-b",
                claim="task-b attempts to reuse task-a evidence",
                evidence_state=EvidenceState.RUNTIME,
                artifact_refs=[foreign.artifact_id],
                verifier_session=self.verifier_session,
                verifier_version="1",
                environment="local",
                evaluator_verdict=EvaluatorVerdict.PASS,
            )
        self.assertEqual(
            self.store.query(
                "SELECT evidence_id FROM evidence_claims WHERE task_id = ?", ("task-b",)
            ),
            [],
        )

    def test_evaluator_required_task_fails_closed_until_independent_pass(self) -> None:
        report = self._artifact("task-evaluator", "test_report", "evaluation")
        for index, verdict in enumerate(
            (
                EvaluatorVerdict.NOT_REQUIRED,
                EvaluatorVerdict.PENDING,
                EvaluatorVerdict.FAIL,
                EvaluatorVerdict.BLOCKED,
            ),
            start=1,
        ):
            self.evidence.record_claim(
                task_id="task-evaluator",
                claim=f"non-passing evaluator state {verdict.value}",
                evidence_state=EvidenceState.RUNTIME,
                artifact_refs=[report.artifact_id],
                verifier_session=self.maker_session,
                verifier_version=str(index),
                environment="local",
                evaluator_verdict=verdict,
            )
            assessment = self.evidence.assess_task("task-evaluator")
            self.assertFalse(assessment.satisfied)
            self.assertIn(
                "independent evaluator verdict is required", assessment.reasons
            )
            with self.assertRaisesRegex(EvidenceError, "independent evaluator"):
                self.evidence.require_task_evidence("task-evaluator")

        accepted = self.evidence.record_claim(
            task_id="task-evaluator",
            claim="independent evaluator accepted the runtime evidence",
            evidence_state=EvidenceState.RUNTIME,
            artifact_refs=[report.artifact_id],
            verifier_session=self.verifier_session,
            verifier_version="1",
            environment="local",
            evaluator_verdict=EvaluatorVerdict.PASS,
        )
        assessment = self.evidence.require_task_evidence("task-evaluator")
        self.assertTrue(assessment.satisfied)
        self.assertIn(accepted.evidence_id, assessment.matching_claim_ids)

    def test_memory_and_active_rule_claims_require_independent_evaluator(self) -> None:
        memory_report = self._artifact("task-a", "test_report", "memory")
        memory_claim = self.evidence.record_claim(
            task_id="task-a",
            claim="held-out evidence supports a durable memory candidate",
            evidence_state=EvidenceState.DURABLE_MEMORY_PROMOTION,
            artifact_refs=[memory_report.artifact_id],
            verifier_session=self.verifier_session,
            verifier_version="1",
            environment="controlled-live",
            evaluator_verdict=EvaluatorVerdict.PASS,
        )
        self.assertEqual(
            memory_claim.verifier_principal_id,
            self.verifier_session.principal_id,
        )

        with self.assertRaisesRegex(AuthorizationError, "owner"):
            self._artifact("task-a", "owner_approval", "forged-owner")
        with self.assertRaisesRegex(AuthorizationError, "system"):
            self._artifact(
                "task-a",
                "rule_promotion_record",
                "non-system-record",
                producer_session=self.verifier_session,
            )

        heldout = self._artifact("task-a", "heldout_eval", "sealed")
        owner_approval = self._artifact(
            "task-a",
            "owner_approval",
            "owner-approved",
            producer_session=self.owner_session,
        )
        promotion_record = self._artifact(
            "task-a", "rule_promotion_record", "limited-to-active"
        )
        active_claim = self.evidence.record_claim(
            task_id="task-a",
            claim="the separately approved rule passed held-out evaluation",
            evidence_state=EvidenceState.ACTIVE_RULE_PROMOTION,
            artifact_refs=[
                heldout.artifact_id,
                owner_approval.artifact_id,
                promotion_record.artifact_id,
            ],
            verifier_session=self.verifier_session,
            verifier_version="1",
            environment="controlled-live",
            evaluator_verdict=EvaluatorVerdict.PASS,
        )
        self.assertEqual(
            active_claim.verifier_principal_id,
            self.verifier_session.principal_id,
        )
        owner_row = self.store.query(
            "SELECT producer_principal_id FROM artifacts WHERE artifact_id = ?",
            (owner_approval.artifact_id,),
        )[0]
        self.assertEqual(
            owner_row["producer_principal_id"], self.owner_session.principal_id
        )

    def test_artifact_idempotency_is_bound_to_authenticated_producer(self) -> None:
        first = self._artifact(
            "task-a", "test_report", "stable", artifact_id="artifact-stable"
        )
        replay = self._artifact(
            "task-a", "test_report", "stable", artifact_id="artifact-stable"
        )
        self.assertEqual(first, replay)
        with self.assertRaisesRegex(IntegrityError, "different content"):
            self._artifact(
                "task-a",
                "test_report",
                "stable",
                producer_session=self.owner_session,
                artifact_id="artifact-stable",
            )


if __name__ == "__main__":
    unittest.main()
