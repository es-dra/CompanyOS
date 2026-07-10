from __future__ import annotations

import gc
import json
import tempfile
import unittest
import uuid
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path
from typing import Any

from companyos_runtime.errors import (
    AuthorizationError,
    ContractError,
    IntegrityError,
    TransitionError,
)
from companyos_runtime.evaluation import (
    ActiveRulePromotionRecord,
    DenyAllEvalResultVerifier,
    DenyAllSealedCustodyVerifier,
    EvaluationRegistry,
    LimitedRulePromotionRecord,
    LimitedRulePromotionRequest,
)
from companyos_runtime.evidence import EvidenceRegistry
from companyos_runtime.kernel import RuntimeKernel
from companyos_runtime.policy import PolicyEngine
from companyos_runtime.scheduler import TaskScheduler
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import (
    Capability,
    EvidenceState,
    EvaluatorVerdict,
    GoalSpec,
    LoopEvent,
    ProposalState,
    TaskSpec,
    canonical_json,
    content_hash,
    utc_now,
)

from tests.evaluation_fixtures import (
    ExactTestEvalVerifier,
    ExactTestSealedCustodyVerifier,
    make_eval_attestation,
    make_sealed_custody_attestation,
)
from tests.identity_fixtures import IdentityFixture


class EvaluationRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        self.kernel = RuntimeKernel(self.store)
        self.kernel.initialize()
        self.identities = IdentityFixture(self.store)
        self.worker = self.identities.worker
        self.evaluator = self.identities.evaluator
        capabilities = (
            Capability.ACTIVE_RULE_PROMOTION,
            Capability.DURABLE_MEMORY_PROMOTION,
        )
        improvement_scope = ("improvement://proposals/**",)
        self.kernel.create_goal(
            project_id="project-1",
            spec=GoalSpec(
                goal_id="goal-1",
                target_outcome="evaluate a bounded improvement candidate",
                success_evidence_states=(EvidenceState.STRUCTURE,),
                allowed_capabilities=capabilities,
                write_scope=improvement_scope,
            ),
            actor=self.identities.owner,
            idempotency_key="goal-create",
        )
        self.kernel.create_run(
            project_id="project-1",
            goal_id="goal-1",
            run_id="run-1",
            actor=self.identities.owner,
            idempotency_key="run-create",
        )
        self.kernel.add_task(
            project_id="project-1",
            run_id="run-1",
            spec=TaskSpec(
                task_id="task-1",
                goal_id="goal-1",
                objective="evaluate and route a proposal",
                expected_delta="quality",
                primary_surface="evaluation://candidate",
                evidence_target=EvidenceState.STRUCTURE,
                capabilities=capabilities,
                write_scope=improvement_scope,
                evaluator_required=True,
                integration_required=False,
            ),
            actor=self.identities.owner,
            idempotency_key="task-create",
        )
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.GOAL_COMPILED,
            actor=self.identities.system,
            idempotency_key="run-compiled",
        )
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.RUN_READY,
            actor=self.identities.system,
            idempotency_key="run-ready",
        )
        scheduler = TaskScheduler(self.store)
        task_claim = scheduler.claim_next(project_id="project-1", worker=self.worker)
        self.assertIsNotNone(task_claim)
        assert task_claim is not None
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.TASK_STARTED,
            actor=self.worker,
            idempotency_key="source-task-started",
            payload={
                "task_id": task_claim.task_id,
                "resource_key": task_claim.resource_key,
                "holder": self.worker.principal_id,
                "fence": task_claim.fence,
            },
        )
        scheduler.start(task_claim, worker=self.worker)
        scheduler.complete(task_claim, worker=self.worker)
        evidence = EvidenceRegistry(self.store)
        artifact = evidence.register_artifact(
            task_id="task-1",
            kind="verification_report",
            uri="artifact://task-1/actual-outcome",
            content_digest=content_hash("bounded rule trial reduced retry friction"),
            producer_session=self.worker,
        )
        self.actual_outcome = (
            "bounded rule trial reduced retry friction in the delivered source task"
        )
        self.source_evidence = evidence.record_claim(
            task_id="task-1",
            claim=self.actual_outcome,
            evidence_state=EvidenceState.STRUCTURE,
            artifact_refs=(artifact.artifact_id,),
            verifier_session=self.evaluator,
            verifier_version="limited-gate-test-v1",
            environment="local",
            evaluator_verdict=EvaluatorVerdict.PASS_WITH_RISK,
            non_claims=("not a real external custody service",),
        )
        self.unaccepted_evidence = evidence.record_claim(
            task_id="task-1",
            claim="a separate passing claim was never accepted by the Task",
            evidence_state=EvidenceState.STRUCTURE,
            artifact_refs=(artifact.artifact_id,),
            verifier_session=self.evaluator,
            verifier_version="limited-gate-test-v1",
            environment="local",
            evaluator_verdict=EvaluatorVerdict.PASS,
            non_claims=("not accepted by task-1",),
        )
        self.failing_evidence = evidence.record_claim(
            task_id="task-1",
            claim="the candidate failed its verification check",
            evidence_state=EvidenceState.STRUCTURE,
            artifact_refs=(artifact.artifact_id,),
            verifier_session=self.evaluator,
            verifier_version="limited-gate-test-v1",
            environment="local",
            evaluator_verdict=EvaluatorVerdict.FAIL,
            non_claims=("does not support limited promotion",),
        )
        self.kernel.accept_task_evidence(
            task_id="task-1",
            actor=self.evaluator,
            idempotency_key="source-evidence-accepted",
            evidence_id=self.source_evidence.evidence_id,
        )
        self.kernel.confirm_task_delivery(
            task_id="task-1",
            actor=self.identities.release,
            idempotency_key="source-task-delivered",
        )
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.EVIDENCE_SUBMITTED,
            actor=self.worker,
            idempotency_key="run-evidence-submitted",
            payload={"task_id": "task-1"},
        )
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.EVALUATOR_VERDICT_RECEIVED,
            actor=self.evaluator,
            idempotency_key="run-evaluator-passed",
            payload={"task_id": "task-1"},
        )
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.DELIVERY_CONFIRMED,
            actor=self.identities.release,
            idempotency_key="source-run-delivered",
        )
        self.registry = EvaluationRegistry(
            self.store,
            result_verifier=ExactTestEvalVerifier(),
            sealed_custody_verifier=ExactTestSealedCustodyVerifier(),
        )
        self.policy = PolicyEngine(self.store)
        self._limited_requests: dict[str, LimitedRulePromotionRequest] = {}

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _proposal(self, label: str = "one"):
        return self.registry.propose(
            project_id="project-1",
            source_run_id="run-1",
            hypothesis=f"candidate {label} improves a bounded metric",
            candidate_digest=content_hash({"candidate": label}),
            editable_surface="prompt_candidate",
            expected_benefit="higher deterministic score",
            risk="possible held-out regression",
            rollback_route="restore prior prompt candidate",
            proposer=self.worker,
            proposal_id=f"proposal-{label}",
        )

    def _eval(
        self,
        proposal,
        *,
        split: str,
        dataset: str,
        status: str = "pass",
        safety_failures=(),
        eval_id: str | None = None,
    ):
        eval_id = eval_id or str(uuid.uuid4())
        dataset_name = f"dataset-{split}"
        dataset_digest = content_hash({"dataset": dataset})
        metrics = {"score": 1.0 if status == "pass" else 0.0}
        attestation = make_eval_attestation(
            eval_id=eval_id,
            project_id="project-1",
            candidate_digest=proposal.candidate_digest,
            dataset_name=dataset_name,
            dataset_split=split,
            dataset_digest=dataset_digest,
            evaluator=self.evaluator,
            evaluator_version="v1",
            status=status,
            metrics=metrics,
            safety_failures=safety_failures,
        )
        return self.registry.record_eval(
            project_id="project-1",
            candidate_digest=proposal.candidate_digest,
            dataset_name=dataset_name,
            dataset_split=split,
            dataset_digest=dataset_digest,
            evaluator=self.evaluator,
            evaluator_version="v1",
            status=status,
            metrics=metrics,
            safety_failures=safety_failures,
            eval_id=eval_id,
            attestation=attestation,
        )

    def _owner_review_proposal(self, label: str = "ready"):
        proposal = self._proposal(label)
        held_in = self._eval(
            proposal,
            split="held_in",
            dataset=f"{label}-held-in",
            eval_id=f"eval-{label}-in",
        )
        self.registry.attach_eval(
            proposal.proposal_id, held_in.eval_id, actor=self.identities.system
        )
        held_out = self._eval(
            proposal,
            split="held_out",
            dataset=f"{label}-held-out",
            eval_id=f"eval-{label}-out",
        )
        return self.registry.attach_eval(
            proposal.proposal_id, held_out.eval_id, actor=self.identities.system
        )

    def _owner_review_for_run(self, label: str, run_id: str):
        proposal = self.registry.propose(
            project_id="project-1",
            source_run_id=run_id,
            hypothesis=f"candidate {label} must not bypass delivery",
            candidate_digest=content_hash({"candidate": label}),
            editable_surface="prompt_candidate",
            expected_benefit="should remain only an expectation",
            risk="promotion before real task evidence",
            rollback_route="restore prior prompt candidate",
            proposer=self.worker,
            proposal_id=f"proposal-{label}",
        )
        held_in = self._eval(
            proposal,
            split="held_in",
            dataset=f"{label}-held-in",
            eval_id=f"eval-{label}-in",
        )
        self.registry.attach_eval(
            proposal.proposal_id, held_in.eval_id, actor=self.identities.system
        )
        held_out = self._eval(
            proposal,
            split="held_out",
            dataset=f"{label}-held-out",
            eval_id=f"eval-{label}-out",
        )
        return self.registry.attach_eval(
            proposal.proposal_id, held_out.eval_id, actor=self.identities.system
        )

    def _delivered_source_with_provenance(
        self,
        label: str,
        *,
        artifact_kind: str,
        artifact_uri: str,
        environment: str,
    ):
        """Create a real public-API source path with caller-selected origin labels."""

        run_id = f"run-{label}"
        task_id = f"task-{label}"
        self.kernel.create_run(
            project_id="project-1",
            goal_id="goal-1",
            run_id=run_id,
            actor=self.identities.owner,
            idempotency_key=f"create-{run_id}",
        )
        self.kernel.add_task(
            project_id="project-1",
            run_id=run_id,
            spec=TaskSpec(
                task_id=task_id,
                goal_id="goal-1",
                objective=f"exercise provenance classifier case {label}",
                expected_delta="bounded verification result",
                primary_surface="evaluation://candidate",
                evidence_target=EvidenceState.STRUCTURE,
                capabilities=(
                    Capability.ACTIVE_RULE_PROMOTION,
                    Capability.DURABLE_MEMORY_PROMOTION,
                ),
                write_scope=("improvement://proposals/**",),
                evaluator_required=True,
                integration_required=False,
            ),
            actor=self.identities.owner,
            idempotency_key=f"create-{task_id}",
        )
        self.kernel.advance_loop(
            run_id=run_id,
            event=LoopEvent.GOAL_COMPILED,
            actor=self.identities.system,
            idempotency_key=f"compile-{run_id}",
        )
        self.kernel.advance_loop(
            run_id=run_id,
            event=LoopEvent.RUN_READY,
            actor=self.identities.system,
            idempotency_key=f"ready-{run_id}",
        )
        scheduler = TaskScheduler(self.store)
        task_claim = scheduler.claim_next(project_id="project-1", worker=self.worker)
        self.assertIsNotNone(task_claim)
        assert task_claim is not None
        self.assertEqual(task_claim.task_id, task_id)
        self.kernel.advance_loop(
            run_id=run_id,
            event=LoopEvent.TASK_STARTED,
            actor=self.worker,
            idempotency_key=f"start-{run_id}",
            payload={
                "task_id": task_id,
                "resource_key": task_claim.resource_key,
                "holder": self.worker.principal_id,
                "fence": task_claim.fence,
            },
        )
        scheduler.start(task_claim, worker=self.worker)
        scheduler.complete(task_claim, worker=self.worker)
        evidence_registry = EvidenceRegistry(self.store)
        artifact = evidence_registry.register_artifact(
            task_id=task_id,
            kind=artifact_kind,
            uri=artifact_uri,
            content_digest=content_hash({"provenance-case": label}),
            producer_session=self.worker,
        )
        outcome = f"case {label} produced a bounded delivered outcome"
        claim = evidence_registry.record_claim(
            task_id=task_id,
            claim=outcome,
            evidence_state=EvidenceState.STRUCTURE,
            artifact_refs=(artifact.artifact_id,),
            verifier_session=self.evaluator,
            verifier_version="promotion-origin-test-v1",
            environment=environment,
            evaluator_verdict=EvaluatorVerdict.PASS,
            non_claims=("origin labels remain subject to promotion classification",),
        )
        self.kernel.accept_task_evidence(
            task_id=task_id,
            actor=self.evaluator,
            idempotency_key=f"accept-{task_id}",
            evidence_id=claim.evidence_id,
        )
        self.kernel.confirm_task_delivery(
            task_id=task_id,
            actor=self.identities.release,
            idempotency_key=f"deliver-{task_id}",
        )
        self.kernel.advance_loop(
            run_id=run_id,
            event=LoopEvent.EVIDENCE_SUBMITTED,
            actor=self.worker,
            idempotency_key=f"evidence-{run_id}",
            payload={"task_id": task_id},
        )
        self.kernel.advance_loop(
            run_id=run_id,
            event=LoopEvent.EVALUATOR_VERDICT_RECEIVED,
            actor=self.evaluator,
            idempotency_key=f"evaluate-{run_id}",
            payload={"task_id": task_id},
        )
        self.kernel.advance_loop(
            run_id=run_id,
            event=LoopEvent.DELIVERY_CONFIRMED,
            actor=self.identities.release,
            idempotency_key=f"deliver-{run_id}",
        )
        proposal = self._owner_review_for_run(label, run_id)
        return proposal, artifact, claim, outcome

    def _limited_request(self, proposal) -> LimitedRulePromotionRequest:
        request = self.registry.build_limited_promotion_request(
            proposal.proposal_id,
            source_task_id="task-1",
            verification_evidence_id=self.source_evidence.evidence_id,
            scope="project://project-1/prompt_candidate/bounded-trial",
            actual_outcome_kind="friction_reduction",
            actual_outcome=self.actual_outcome,
            non_goals=("other projects", "public release", "business validation"),
            review_condition="review after the next bounded project-1 trial",
            rollback_or_retirement_path=proposal.rollback_route,
            non_claim_boundary="supports only the stated project-1 trial scope",
        )
        self._limited_requests[proposal.proposal_id] = request
        return request

    def _approval(
        self,
        proposal,
        target: ProposalState,
        capability: Capability,
        *,
        limited_request: LimitedRulePromotionRequest | None = None,
    ):
        if target is ProposalState.LIMITED and limited_request is None:
            limited_request = self._limited_requests.get(proposal.proposal_id)
            if limited_request is None:
                limited_request = self._limited_request(proposal)
        digest = self.registry.promotion_request_digest(
            proposal.proposal_id,
            proposal.candidate_digest,
            target,
            limited_request=limited_request,
        )
        return self.policy.record_approval(
            project_id="project-1",
            goal_id="goal-1",
            run_id="run-1",
            task_id="task-1",
            requester=self.worker,
            approver=self.identities.owner,
            capability=capability,
            action=f"promote_improvement:{target.value}",
            resource=self.registry.promotion_resource(proposal.proposal_id),
            request_digest=digest,
            policy_version="companyos-policy-v1",
            decision="approved",
            ttl_seconds=600,
        )

    def _sealed_fixture(self, label: str):
        proposal = self._owner_review_proposal(label)
        limited_approval = self._approval(
            proposal, ProposalState.LIMITED, Capability.ACTIVE_RULE_PROMOTION
        )
        limited = self.registry.promote(
            proposal.proposal_id,
            target=ProposalState.LIMITED,
            approval_id=limited_approval.approval_id,
            actor=self.identities.owner,
            limited_request=self._limited_requests[proposal.proposal_id],
        )
        sealed = self._eval(
            limited,
            split="sealed",
            dataset=f"{label}-sealed",
            eval_id=f"eval-{label}-sealed",
        )
        limited = self.registry.attach_eval(
            proposal.proposal_id,
            sealed.eval_id,
            actor=self.identities.system,
        )
        custody = make_sealed_custody_attestation(
            proposal_id=proposal.proposal_id,
            eval_id=sealed.eval_id,
            project_id="project-1",
            candidate_digest=proposal.candidate_digest,
            dataset_digest=sealed.dataset_digest,
            eval_attestation_digest=sealed.attestation_digest,
            evaluator=self.evaluator,
        )
        return proposal, limited_approval, limited, sealed, custody

    def _active_fixture(self, label: str):
        proposal, limited_approval, limited, sealed, custody = self._sealed_fixture(
            label
        )
        self.registry.record_sealed_custody_attestation(
            proposal.proposal_id, attestation=custody
        )
        active_approval = self._approval(
            limited, ProposalState.ACTIVE, Capability.ACTIVE_RULE_PROMOTION
        )
        self.registry.promote(
            proposal.proposal_id,
            target=ProposalState.ACTIVE,
            approval_id=active_approval.approval_id,
            actor=self.identities.owner,
        )
        return proposal, limited_approval, sealed, active_approval

    def _rewrite_event_history(self, mutate) -> None:
        """Simulate a privileged full-history rewrite with a valid hash chain."""

        connection = self.store.connect()
        try:
            connection.execute("DROP TRIGGER events_no_update")
            connection.execute("BEGIN IMMEDIATE")
            mutate(connection)
            previous_hash = "GENESIS"
            rows = connection.execute("SELECT * FROM events ORDER BY seq").fetchall()
            for row in rows:
                payload_digest = content_hash(row["payload_json"])
                envelope = {
                    "event_id": row["event_id"],
                    "aggregate_type": row["aggregate_type"],
                    "aggregate_id": row["aggregate_id"],
                    "aggregate_version": row["aggregate_version"],
                    "project_id": row["project_id"],
                    "run_id": row["run_id"],
                    "task_id": row["task_id"],
                    "event_type": row["event_type"],
                    "schema_version": row["schema_version"],
                    "actor": row["actor"],
                    "auth_context": json.loads(row["auth_context_json"]),
                    "command_id": row["command_id"],
                    "idempotency_key": row["idempotency_key"],
                    "correlation_id": row["correlation_id"],
                    "causation_id": row["causation_id"],
                    "policy_version": row["policy_version"],
                    "occurred_at": row["occurred_at"],
                    "recorded_at": row["recorded_at"],
                    "confidentiality": row["confidentiality"],
                    "payload_digest": payload_digest,
                    "previous_event_hash": previous_hash,
                }
                event_hash = content_hash(previous_hash + canonical_json(envelope))
                connection.execute(
                    "UPDATE events SET payload_digest = ?, previous_event_hash = ?, "
                    "event_hash = ? WHERE seq = ?",
                    (payload_digest, previous_hash, event_hash, row["seq"]),
                )
                previous_hash = event_hash
            connection.commit()
        finally:
            connection.close()
            self.store.initialize()

    @staticmethod
    def _promotion_event(connection, proposal_id: str, target: str):
        rows = connection.execute(
            "SELECT * FROM events WHERE aggregate_type = 'improvement' "
            "AND aggregate_id = ? AND event_type = 'improvement_promoted' "
            "ORDER BY seq",
            (proposal_id,),
        ).fetchall()
        return next(
            row for row in rows if json.loads(row["payload_json"]).get("to") == target
        )

    @staticmethod
    def _approval_event(connection, approval_id: str):
        return connection.execute(
            "SELECT * FROM events WHERE aggregate_type = 'approval' "
            "AND aggregate_id = ? AND event_type = 'approval_decided'",
            (approval_id,),
        ).fetchone()

    def test_protected_or_unknown_surface_cannot_enter_self_improvement(self) -> None:
        for surface in ("authority_order", "capability_policy", "unknown_surface"):
            with self.subTest(surface=surface):
                with self.assertRaises(AuthorizationError):
                    self.registry.propose(
                        project_id="project-1",
                        source_run_id="run-1",
                        hypothesis="attempt protected mutation",
                        candidate_digest=content_hash({"surface": surface}),
                        editable_surface=surface,
                        expected_benefit="none",
                        risk="unsafe",
                        rollback_route="reject",
                        proposer=self.worker,
                    )
        self.assertEqual(self.store.query("SELECT * FROM improvement_proposals"), [])

    def test_held_out_requires_clean_held_in_and_an_isolated_dataset(self) -> None:
        proposal = self._proposal("isolation")
        premature = self._eval(
            proposal,
            split="held_out",
            dataset="premature",
            eval_id="eval-premature",
        )
        with self.assertRaises(TransitionError):
            self.registry.attach_eval(
                proposal.proposal_id,
                premature.eval_id,
                actor=self.identities.system,
            )

        held_in = self._eval(
            proposal,
            split="held_in",
            dataset="shared-dataset",
            eval_id="eval-isolation-in",
        )
        pending = self.registry.attach_eval(
            proposal.proposal_id, held_in.eval_id, actor=self.identities.system
        )
        self.assertEqual(pending.state, ProposalState.HELDOUT_PENDING)

        contaminated = self._eval(
            proposal,
            split="held_out",
            dataset="shared-dataset",
            eval_id="eval-contaminated-out",
        )
        with self.assertRaises(ContractError):
            self.registry.attach_eval(
                proposal.proposal_id,
                contaminated.eval_id,
                actor=self.identities.system,
            )

        isolated = self._eval(
            proposal,
            split="held_out",
            dataset="isolated-dataset",
            eval_id="eval-isolated-out",
        )
        ready = self.registry.attach_eval(
            proposal.proposal_id, isolated.eval_id, actor=self.identities.system
        )
        self.assertEqual(ready.state, ProposalState.OWNER_REVIEW)

    def test_any_safety_failure_rejects_even_a_nominal_pass(self) -> None:
        proposal = self._proposal("safety")
        unsafe = self._eval(
            proposal,
            split="held_in",
            dataset="safety-held-in",
            status="pass",
            safety_failures=("protected capability boundary regressed",),
            eval_id="eval-safety",
        )
        self.assertFalse(unsafe.clean_pass)
        rejected = self.registry.attach_eval(
            proposal.proposal_id, unsafe.eval_id, actor=self.identities.system
        )
        self.assertEqual(rejected.state, ProposalState.REJECTED)

    def test_eval_recording_requires_session_exact_attestation_and_verifier(
        self,
    ) -> None:
        proposal = self._proposal("attestation")
        eval_id = "eval-attestation"
        dataset_name = "dataset-held_in"
        dataset_digest = content_hash({"dataset": "attestation-held-in"})
        metrics = {"score": 1.0}
        attestation = make_eval_attestation(
            eval_id=eval_id,
            project_id="project-1",
            candidate_digest=proposal.candidate_digest,
            dataset_name=dataset_name,
            dataset_split="held_in",
            dataset_digest=dataset_digest,
            evaluator=self.evaluator,
            evaluator_version="v1",
            status="pass",
            metrics=metrics,
        )
        values: dict[str, Any] = {
            "project_id": "project-1",
            "candidate_digest": proposal.candidate_digest,
            "dataset_name": dataset_name,
            "dataset_split": "held_in",
            "dataset_digest": dataset_digest,
            "evaluator_version": "v1",
            "status": "pass",
            "metrics": metrics,
            "eval_id": eval_id,
        }

        with self.assertRaisesRegex(AuthorizationError, "no trusted runner"):
            DenyAllEvalResultVerifier().verify(attestation)
        with self.assertRaisesRegex(AuthorizationError, "authenticated session"):
            self.registry.record_eval(
                **values,
                evaluator="evaluator-forgery",  # type: ignore[arg-type]
                attestation=attestation,
            )
        with self.assertRaisesRegex(AuthorizationError, "exactly match"):
            self.registry.record_eval(
                **values,
                evaluator=self.evaluator,
                attestation=replace(attestation, status="fail"),
            )
        recorded = self.registry.record_eval(
            **values,
            evaluator=self.evaluator,
            attestation=attestation,
        )
        self.assertEqual(recorded.attestation_id, attestation.attestation_id)
        self.assertEqual(len(recorded.attestation_digest), 64)
        persisted = self.store.query(
            "SELECT attestation_id, attestation_digest FROM eval_runs WHERE eval_id = ?",
            (eval_id,),
        )[0]
        self.assertEqual(persisted["attestation_id"], attestation.attestation_id)
        self.assertEqual(persisted["attestation_digest"], recorded.attestation_digest)
        self.assertNotIn(attestation.proof, persisted.values())

    def test_limited_and_active_promotion_each_require_exact_active_rule_approval(
        self,
    ) -> None:
        proposal = self._owner_review_proposal()
        limited_request = self._limited_request(proposal)
        with self.assertRaises(AuthorizationError):
            self.registry.promote(
                proposal.proposal_id,
                target=ProposalState.LIMITED,
                approval_id="missing-approval",
                actor=self.identities.owner,
                limited_request=limited_request,
            )

        wrong_capability = self._approval(
            proposal, ProposalState.LIMITED, Capability.ACTIVE_RULE_PROMOTION
        )
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE approvals SET capability = ? WHERE approval_id = ?",
                (
                    Capability.DURABLE_MEMORY_PROMOTION.value,
                    wrong_capability.approval_id,
                ),
            )
        with self.assertRaises(AuthorizationError):
            self.registry.promote(
                proposal.proposal_id,
                target=ProposalState.LIMITED,
                approval_id=wrong_capability.approval_id,
                actor=self.identities.owner,
                limited_request=limited_request,
            )

        limited_approval = self._approval(
            proposal, ProposalState.LIMITED, Capability.ACTIVE_RULE_PROMOTION
        )
        limited = self.registry.promote(
            proposal.proposal_id,
            target=ProposalState.LIMITED,
            approval_id=limited_approval.approval_id,
            actor=self.identities.owner,
            limited_request=limited_request,
        )
        self.assertEqual(limited.state, ProposalState.LIMITED)

        with self.assertRaises(TransitionError):
            self.registry.promote(
                proposal.proposal_id,
                target=ProposalState.ACTIVE,
                approval_id=limited_approval.approval_id,
                actor=self.identities.owner,
            )
        sealed = self._eval(
            limited,
            split="sealed",
            dataset="ready-sealed-audit",
            eval_id="eval-ready-sealed",
        )
        limited = self.registry.attach_eval(
            proposal.proposal_id, sealed.eval_id, actor=self.identities.system
        )
        self.assertEqual(limited.state, ProposalState.LIMITED)
        with self.assertRaises(AuthorizationError):
            self.registry.promote(
                proposal.proposal_id,
                target=ProposalState.ACTIVE,
                approval_id=limited_approval.approval_id,
                actor=self.identities.owner,
            )
        custody = make_sealed_custody_attestation(
            proposal_id=proposal.proposal_id,
            eval_id=sealed.eval_id,
            project_id="project-1",
            candidate_digest=proposal.candidate_digest,
            dataset_digest=sealed.dataset_digest,
            eval_attestation_digest=sealed.attestation_digest,
            evaluator=self.evaluator,
        )
        self.registry.record_sealed_custody_attestation(
            proposal.proposal_id, attestation=custody
        )
        active_approval = self._approval(
            limited, ProposalState.ACTIVE, Capability.ACTIVE_RULE_PROMOTION
        )
        active = self.registry.promote(
            proposal.proposal_id,
            target=ProposalState.ACTIVE,
            approval_id=active_approval.approval_id,
            actor=self.identities.owner,
        )
        self.assertEqual(active.state, ProposalState.ACTIVE)
        self.assertEqual(active.owner_approval_id, active_approval.approval_id)

    def test_sealed_result_recorded_before_limited_cannot_be_attached_later(
        self,
    ) -> None:
        proposal = self._owner_review_proposal()
        early_sealed = self._eval(
            proposal,
            split="sealed",
            dataset="premature-sealed-dataset",
            eval_id="eval-premature-sealed",
        )
        limited_approval = self._approval(
            proposal, ProposalState.LIMITED, Capability.ACTIVE_RULE_PROMOTION
        )
        self.registry.promote(
            proposal.proposal_id,
            target=ProposalState.LIMITED,
            approval_id=limited_approval.approval_id,
            actor=self.identities.owner,
            limited_request=self._limited_requests[proposal.proposal_id],
        )
        with self.assertRaisesRegex(TransitionError, "after limited promotion"):
            self.registry.attach_eval(
                proposal.proposal_id,
                early_sealed.eval_id,
                actor=self.identities.system,
            )

    def test_limited_rejects_intake_or_ready_source_run_and_task(self) -> None:
        for label, ready in (("intake-source", False), ("ready-source", True)):
            with self.subTest(label=label):
                run_id = f"run-{label}"
                task_id = f"task-{label}"
                self.kernel.create_run(
                    project_id="project-1",
                    goal_id="goal-1",
                    run_id=run_id,
                    actor=self.identities.owner,
                    idempotency_key=f"create-{run_id}",
                )
                self.kernel.add_task(
                    project_id="project-1",
                    run_id=run_id,
                    spec=TaskSpec(
                        task_id=task_id,
                        goal_id="goal-1",
                        objective="must not become limited before delivery",
                        expected_delta="none before evidence",
                        primary_surface="evaluation://premature",
                        evidence_target=EvidenceState.STRUCTURE,
                        capabilities=(Capability.ACTIVE_RULE_PROMOTION,),
                        evaluator_required=True,
                        integration_required=False,
                    ),
                    actor=self.identities.owner,
                    idempotency_key=f"create-{task_id}",
                )
                if ready:
                    self.kernel.advance_loop(
                        run_id=run_id,
                        event=LoopEvent.GOAL_COMPILED,
                        actor=self.identities.system,
                        idempotency_key=f"compile-{run_id}",
                    )
                    self.kernel.advance_loop(
                        run_id=run_id,
                        event=LoopEvent.RUN_READY,
                        actor=self.identities.system,
                        idempotency_key=f"ready-{run_id}",
                    )
                proposal = self._owner_review_for_run(label, run_id)
                with self.assertRaisesRegex(
                    TransitionError, "delivered source Run and Task"
                ):
                    self.registry.build_limited_promotion_request(
                        proposal.proposal_id,
                        source_task_id=task_id,
                        verification_evidence_id=self.source_evidence.evidence_id,
                        scope=f"project://project-1/{label}",
                        actual_outcome_kind="benefit",
                        actual_outcome=self.actual_outcome,
                        non_goals=("all other tasks",),
                        review_condition="review only after delivery",
                        rollback_or_retirement_path=proposal.rollback_route,
                        non_claim_boundary="no limited status",
                    )

    def test_limited_requires_the_exact_accepted_passing_evidence(self) -> None:
        proposal = self._owner_review_proposal("exact-source-evidence")
        for evidence, error in (
            (self.failing_evidence, "passing verification evidence"),
            (self.unaccepted_evidence, "accepted before exact Task/Run delivery"),
        ):
            with self.subTest(evidence_id=evidence.evidence_id):
                with self.assertRaisesRegex((TransitionError, IntegrityError), error):
                    self.registry.build_limited_promotion_request(
                        proposal.proposal_id,
                        source_task_id="task-1",
                        verification_evidence_id=evidence.evidence_id,
                        scope="project://project-1/prompt_candidate/exact-evidence",
                        actual_outcome_kind="benefit",
                        actual_outcome=evidence.claim,
                        non_goals=("other evidence",),
                        review_condition="review after another bounded task",
                        rollback_or_retirement_path=proposal.rollback_route,
                        non_claim_boundary="only this accepted claim may support promotion",
                    )
        with self.assertRaisesRegex(ContractError, "exactly equal"):
            self.registry.build_limited_promotion_request(
                proposal.proposal_id,
                source_task_id="task-1",
                verification_evidence_id=self.source_evidence.evidence_id,
                scope="project://project-1/prompt_candidate/exact-evidence",
                actual_outcome_kind="benefit",
                actual_outcome="an unverified free-text benefit",
                non_goals=("other evidence",),
                review_condition="review after another bounded task",
                rollback_or_retirement_path=proposal.rollback_route,
                non_claim_boundary="only this accepted claim may support promotion",
            )

    def test_limited_public_api_rejects_non_real_and_unknown_origin_aliases(
        self,
    ) -> None:
        cases = (
            (
                "origin-env-test-double",
                "verification_report",
                "artifact://origin/env-test-double",
                "test-double",
            ),
            (
                "origin-kind-synthetic",
                " SyNtHeTiC ",
                "artifact://origin/kind-synthetic",
                "local",
            ),
            (
                "origin-uri-mock",
                "verification_report",
                "mock://origin/uri-mock",
                "local",
            ),
            (
                "origin-encoded-alias",
                "verification_report",
                "artifact://origin/encoded-alias",
                " %54EST__DOUBLE ",
            ),
            (
                "origin-unicode-alias",
                "verification_report",
                "artifact://origin/unicode-alias",
                "ＴＥＳＴ＿ＤＯＵＢＬＥ",
            ),
            (
                "origin-encoded-uri",
                "verification_report",
                " m%6Fck://origin/encoded-uri ",
                "LOCAL",
            ),
            (
                "origin-unknown-kind",
                "unclassified_report",
                "artifact://origin/unknown-kind",
                "local",
            ),
            (
                "origin-unknown-scheme",
                "verification_report",
                "custom-origin://origin/unknown-scheme",
                "local",
            ),
            (
                "origin-malformed-real-scheme",
                "verification_report",
                "https:local-label-only",
                "local",
            ),
        )
        for label, artifact_kind, artifact_uri, environment in cases:
            with self.subTest(label=label):
                proposal, _, claim, outcome = self._delivered_source_with_provenance(
                    label,
                    artifact_kind=artifact_kind,
                    artifact_uri=artifact_uri,
                    environment=environment,
                )
                with self.assertRaisesRegex(
                    TransitionError, "real-task evidence provenance"
                ):
                    self.registry.build_limited_promotion_request(
                        proposal.proposal_id,
                        source_task_id=claim.task_id,
                        verification_evidence_id=claim.evidence_id,
                        scope=f"project://project-1/{label}",
                        actual_outcome_kind="bounded_result",
                        actual_outcome=outcome,
                        non_goals=("all other origins",),
                        review_condition="review after one bounded trial",
                        rollback_or_retirement_path=proposal.rollback_route,
                        non_claim_boundary="origin classifier must pass before promotion",
                    )

    def test_active_readback_rejects_rehashed_non_real_source_origin(self) -> None:
        proposal, _, _, _ = self._active_fixture("source-origin-rehash")
        artifact_id = self.source_evidence.artifact_refs[0]

        def mutate(connection) -> None:
            connection.execute(
                "UPDATE artifacts SET kind = ? WHERE artifact_id = ?",
                (" %53YNTHETIC ", artifact_id),
            )
            event = connection.execute(
                "SELECT * FROM events WHERE aggregate_type = 'artifact' "
                "AND aggregate_id = ? AND event_type = 'artifact_registered'",
                (artifact_id,),
            ).fetchone()
            payload = json.loads(event["payload_json"])
            payload["kind"] = " %53YNTHETIC "
            connection.execute(
                "UPDATE events SET payload_json = ? WHERE seq = ?",
                (canonical_json(payload), event["seq"]),
            )

        self._rewrite_event_history(mutate)
        self.assertEqual(
            self.store.verify_event_chain(),
            len(self.store.query("SELECT 1 FROM events")),
        )
        with self.assertRaisesRegex(TransitionError, "real-task evidence provenance"):
            self.registry.get_active_rule_promotion_record(proposal.proposal_id)

    def test_active_readback_rejects_source_origin_projection_only_tamper(
        self,
    ) -> None:
        proposal, _, _, _ = self._active_fixture("source-origin-projection")
        artifact_id = self.source_evidence.artifact_refs[0]
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE artifacts SET uri = ? WHERE artifact_id = ?",
                ("mock://projection-only", artifact_id),
            )
        with self.assertRaisesRegex(IntegrityError, "artifact projection/event"):
            self.registry.get_active_rule_promotion_record(proposal.proposal_id)

    def test_limited_owner_approval_digest_binds_all_decision_fields(self) -> None:
        proposal = self._owner_review_proposal("limited-binding")
        request = self._limited_request(proposal)
        approval = self._approval(
            proposal, ProposalState.LIMITED, Capability.ACTIVE_RULE_PROMOTION
        )
        drifted_scope = replace(
            request, scope="project://project-1/prompt_candidate/drifted-scope"
        )
        with self.assertRaisesRegex(AuthorizationError, "exact, live owner approval"):
            self.registry.promote(
                proposal.proposal_id,
                target=ProposalState.LIMITED,
                approval_id=approval.approval_id,
                actor=self.identities.owner,
                limited_request=drifted_scope,
            )
        drifted_digest = replace(request, verification_evidence_digest="b" * 64)
        with self.assertRaisesRegex(IntegrityError, "drifted"):
            self.registry.promote(
                proposal.proposal_id,
                target=ProposalState.LIMITED,
                approval_id=approval.approval_id,
                actor=self.identities.owner,
                limited_request=drifted_digest,
            )

    def test_direct_limited_request_cannot_replace_persisted_authority(self) -> None:
        proposal = self._owner_review_proposal("direct-request-authority")
        canonical = self._limited_request(proposal)
        with self.assertRaises(ContractError):
            replace(
                canonical,
                scope="project://project-1/%2e%2e/cross-project",
            )
        forged_requests = (
            replace(
                canonical,
                scope="project://project-2/prompt_candidate/cross-project",
            ),
            replace(canonical, source_run_id="run-forged"),
            replace(canonical, source_task_id="task-forged"),
            replace(
                canonical,
                verification_evidence_id=self.unaccepted_evidence.evidence_id,
            ),
        )
        for index, forged in enumerate(forged_requests):
            with self.subTest(index=index):
                approval = self._approval(
                    proposal,
                    ProposalState.LIMITED,
                    Capability.ACTIVE_RULE_PROMOTION,
                    limited_request=forged,
                )
                with self.assertRaises(
                    (ContractError, IntegrityError, TransitionError)
                ):
                    self.registry.promote(
                        proposal.proposal_id,
                        target=ProposalState.LIMITED,
                        approval_id=approval.approval_id,
                        actor=self.identities.owner,
                        limited_request=forged,
                    )

    def test_free_text_reason_cannot_forge_accepted_evidence_linkage(self) -> None:
        proposal, _, _, _ = self._active_fixture("typed-evidence-link")

        def mutate(connection) -> None:
            events = connection.execute(
                "SELECT * FROM events WHERE aggregate_type = 'task' "
                "AND aggregate_id = 'task-1' AND event_type = 'task_state_changed'"
            ).fetchall()
            event = next(
                item
                for item in events
                if json.loads(item["payload_json"]).get("accepted_evidence_id")
                == self.source_evidence.evidence_id
            )
            payload = json.loads(event["payload_json"])
            payload.pop("accepted_evidence_id")
            self.assertIn("authoritative evidence accepted", payload["reason"])
            connection.execute(
                "UPDATE events SET payload_json = ? WHERE seq = ?",
                (canonical_json(payload), event["seq"]),
            )

        self._rewrite_event_history(mutate)
        self.assertEqual(
            self.store.verify_event_chain(),
            len(self.store.query("SELECT 1 FROM events")),
        )
        with self.assertRaisesRegex(IntegrityError, "must be accepted"):
            self.registry.get_active_rule_promotion_record(proposal.proposal_id)

    def test_sealed_external_custody_is_default_deny_and_exact(self) -> None:
        proposal = self._owner_review_proposal("custody-default-deny")
        limited_approval = self._approval(
            proposal, ProposalState.LIMITED, Capability.ACTIVE_RULE_PROMOTION
        )
        limited = self.registry.promote(
            proposal.proposal_id,
            target=ProposalState.LIMITED,
            approval_id=limited_approval.approval_id,
            actor=self.identities.owner,
            limited_request=self._limited_requests[proposal.proposal_id],
        )
        sealed = self._eval(
            limited,
            split="sealed",
            dataset="custody-default-deny-sealed",
            eval_id="eval-custody-default-deny-sealed",
        )
        self.registry.attach_eval(
            proposal.proposal_id, sealed.eval_id, actor=self.identities.system
        )
        custody = make_sealed_custody_attestation(
            proposal_id=proposal.proposal_id,
            eval_id=sealed.eval_id,
            project_id="project-1",
            candidate_digest=proposal.candidate_digest,
            dataset_digest=sealed.dataset_digest,
            eval_attestation_digest=sealed.attestation_digest,
            evaluator=self.evaluator,
        )
        with self.assertRaisesRegex(AuthorizationError, "no trusted external"):
            DenyAllSealedCustodyVerifier().verify(custody)
        forged = replace(custody, dataset_digest="b" * 64)
        with self.assertRaisesRegex(AuthorizationError, "does not exactly match"):
            self.registry.record_sealed_custody_attestation(
                proposal.proposal_id, attestation=forged
            )
        with self.assertRaisesRegex(AuthorizationError, "external sealed custody"):
            self.registry.promotion_request_digest(
                proposal.proposal_id,
                proposal.candidate_digest,
                ProposalState.ACTIVE,
            )

    def test_raw_protected_events_require_exact_handler_capability(self) -> None:
        protected_events = (
            ("approval", "approval_decided"),
            ("artifact", "artifact_registered"),
            ("evidence", "evidence_claim_recorded"),
            ("eval", "eval_recorded"),
            ("improvement", "improvement_proposed"),
            ("sealed_custody", "sealed_custody_attested"),
        )
        for index, (aggregate_type, event_type) in enumerate(protected_events):
            with self.subTest(aggregate_type=aggregate_type, event_type=event_type):
                with self.assertRaisesRegex(
                    IntegrityError, "protected event requires opaque command authority"
                ):
                    with self.store.transaction(immediate=True) as connection:
                        self.store.append_event(
                            connection,
                            aggregate_type=aggregate_type,
                            aggregate_id=f"raw-protected-{index}",
                            expected_version=0,
                            project_id="project-1",
                            event_type=event_type,
                            actor=self.worker.principal_id,
                            command_id=f"raw-protected-command-{index}",
                            correlation_id=f"raw-protected-{index}",
                            policy_version="companyos-policy-v1",
                            payload={"forged": True},
                        )

    def test_protected_capability_cannot_be_borrowed_or_cross_stores(self) -> None:
        authority = object.__getattribute__(
            self.registry, "_EvaluationRegistry__command_authority"
        )
        with self.assertRaisesRegex(
            IntegrityError, "protected event requires opaque command authority"
        ):
            with self.store.transaction(immediate=True) as connection:
                self.store.append_event(
                    connection,
                    aggregate_type="sealed_custody",
                    aggregate_id=str(uuid.uuid4()),
                    expected_version=0,
                    project_id="project-1",
                    event_type="sealed_custody_attested",
                    actor="borrowed-capability",
                    command_id=str(uuid.uuid4()),
                    correlation_id="borrowed-capability",
                    policy_version="companyos-policy-v1",
                    payload={"forged": True},
                    command_authority=authority,
                    command_owner=object(),
                )

        with tempfile.TemporaryDirectory() as other_temp:
            other_store = SQLiteStore(Path(other_temp) / "runtime.db")
            other_store.initialize()
            with self.assertRaisesRegex(
                IntegrityError, "protected event requires opaque command authority"
            ):
                with other_store.transaction(immediate=True) as connection:
                    other_store.append_event(
                        connection,
                        aggregate_type="sealed_custody",
                        aggregate_id="cross-store-custody",
                        expected_version=0,
                        project_id="project-1",
                        event_type="sealed_custody_attested",
                        actor="cross-store-capability",
                        command_id="cross-store-command",
                        correlation_id="cross-store-custody",
                        policy_version="companyos-policy-v1",
                        payload={"forged": True},
                        command_authority=authority,
                        command_owner=self.registry,
                    )

    def test_verifier_identity_spoof_cannot_create_a_second_registry(self) -> None:
        class MissingAuthorityIdVerifier:
            def verify(self, attestation) -> None:
                del attestation

        class AcceptAllCustodyVerifier:
            authority_id = ExactTestSealedCustodyVerifier.authority_id

            def verify(self, attestation) -> None:
                del attestation

        same_database = SQLiteStore(self.store.path)
        with self.assertRaisesRegex(AuthorizationError, "non-empty authority_id"):
            EvaluationRegistry(
                same_database,
                result_verifier=ExactTestEvalVerifier(),
                sealed_custody_verifier=MissingAuthorityIdVerifier(),
            )
        with self.assertRaisesRegex(
            IntegrityError, "evaluation registry authority is already bound"
        ):
            EvaluationRegistry(
                same_database,
                result_verifier=ExactTestEvalVerifier(),
                sealed_custody_verifier=AcceptAllCustodyVerifier(),
            )
        with self.assertRaises(AttributeError):
            self.registry.sealed_custody_verifier = (  # type: ignore[misc]
                AcceptAllCustodyVerifier()
            )

    def test_verifier_implementation_type_is_pinned_after_registry_retirement(
        self,
    ) -> None:
        class ClaimedAuthorityIdVerifier:
            authority_id = ExactTestSealedCustodyVerifier.authority_id

            def verify(self, attestation) -> None:
                del attestation

        class SpoofedCustodyVerifier:
            authority_id = ExactTestSealedCustodyVerifier.authority_id

            def verify(self, attestation) -> None:
                del attestation

        SpoofedCustodyVerifier.__module__ = ExactTestSealedCustodyVerifier.__module__
        SpoofedCustodyVerifier.__qualname__ = (
            ExactTestSealedCustodyVerifier.__qualname__
        )
        with tempfile.TemporaryDirectory() as isolated_temp:
            path = Path(isolated_temp) / "runtime.db"
            first_store = SQLiteStore(path)
            first_store.initialize()
            trusted_registry = EvaluationRegistry(
                first_store,
                result_verifier=ExactTestEvalVerifier(),
                sealed_custody_verifier=ExactTestSealedCustodyVerifier(),
            )
            del trusted_registry
            gc.collect()
            replacement_store = SQLiteStore(path)
            with self.assertRaisesRegex(
                IntegrityError, "protected handler configuration drift"
            ):
                EvaluationRegistry(
                    replacement_store,
                    result_verifier=ExactTestEvalVerifier(),
                    sealed_custody_verifier=ClaimedAuthorityIdVerifier(),
                )
            with self.assertRaisesRegex(
                IntegrityError, "protected handler implementation drift"
            ):
                EvaluationRegistry(
                    replacement_store,
                    result_verifier=ExactTestEvalVerifier(),
                    sealed_custody_verifier=SpoofedCustodyVerifier(),
                )

    def test_raw_custody_append_and_projection_cannot_unlock_active(self) -> None:
        proposal, _, _, sealed, custody = self._sealed_fixture("raw-custody-forgery")
        envelope = asdict(custody)
        envelope.pop("proof")
        attestation_digest = content_hash(envelope)
        verified_at = utc_now()
        payload = {
            **envelope,
            "attestation_digest": attestation_digest,
            "verified_at": verified_at,
        }
        with self.assertRaisesRegex(
            IntegrityError, "protected event requires opaque command authority"
        ):
            with self.store.transaction(immediate=True) as connection:
                self.store.append_event(
                    connection,
                    aggregate_type="sealed_custody",
                    aggregate_id=custody.attestation_id,
                    expected_version=0,
                    project_id="project-1",
                    run_id=proposal.source_run_id,
                    event_type="sealed_custody_attested",
                    actor=custody.custodian_id,
                    command_id="raw-custody-command",
                    correlation_id=proposal.source_run_id,
                    policy_version="companyos-policy-v1",
                    payload=payload,
                )
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO sealed_custody_attestations(
                    attestation_id, proposal_id, eval_id, project_id,
                    candidate_digest, dataset_digest, eval_attestation_digest,
                    evaluator_principal_id, custody_provider, custodian_id,
                    policy_version, attestation_digest, verified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    custody.attestation_id,
                    proposal.proposal_id,
                    sealed.eval_id,
                    "project-1",
                    proposal.candidate_digest,
                    sealed.dataset_digest,
                    sealed.attestation_digest,
                    sealed.evaluator,
                    custody.custody_provider,
                    custody.custodian_id,
                    "companyos-policy-v1",
                    attestation_digest,
                    verified_at,
                ),
            )
        with self.assertRaisesRegex(IntegrityError, "custody authority event"):
            self.registry.record_sealed_custody_attestation(
                proposal.proposal_id, attestation=custody
            )
        with self.assertRaisesRegex(IntegrityError, "custody authority event"):
            self.registry.promotion_request_digest(
                proposal.proposal_id,
                proposal.candidate_digest,
                ProposalState.ACTIVE,
            )

    def test_active_readback_rejects_sealed_custody_projection_tamper(self) -> None:
        proposal, _, _, _ = self._active_fixture("custody-readback-tamper")
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE sealed_custody_attestations SET attestation_digest = ? "
                "WHERE proposal_id = ?",
                ("b" * 64, proposal.proposal_id),
            )
        with self.assertRaisesRegex(IntegrityError, "custody"):
            self.registry.get_active_rule_promotion_record(proposal.proposal_id)

    def test_active_readback_rejects_approval_projection_tamper_matrix(
        self,
    ) -> None:
        cases = (
            ("capability", Capability.DURABLE_MEMORY_PROMOTION.value),
            ("decision", "denied"),
            ("project_id", "project-forgery"),
            ("run_id", "run-forgery"),
            ("requester", self.evaluator.principal_id),
            ("approver", self.evaluator.principal_id),
            ("action", "promote_improvement:limited"),
            ("resource", "improvement://proposals/forgery"),
            ("request_digest", content_hash({"forgery": "digest"})),
            ("policy_version", "forged-policy"),
            ("requested_at", "2000-01-01T00:00:00Z"),
        )
        for index, (field, value) in enumerate(cases):
            with self.subTest(field=field):
                proposal, _, _, active_approval = self._active_fixture(
                    f"authority-{index}"
                )
                connection = self.store.connect()
                try:
                    connection.execute("PRAGMA foreign_keys = OFF")
                    connection.execute(
                        f"UPDATE approvals SET {field} = ? WHERE approval_id = ?",
                        (value, active_approval.approval_id),
                    )
                finally:
                    connection.close()
                with self.assertRaisesRegex(IntegrityError, "approval"):
                    self.registry.get_active_rule_promotion_record(proposal.proposal_id)

    def test_active_readback_checks_chain_before_authority_projections(self) -> None:
        proposal, _, _, active_approval = self._active_fixture("chain-first")
        connection = self.store.connect()
        try:
            connection.execute("DROP TRIGGER events_no_update")
            event = self._approval_event(connection, active_approval.approval_id)
            connection.execute(
                "UPDATE events SET actor = ? WHERE seq = ?",
                (self.evaluator.principal_id, event["seq"]),
            )
            connection.execute(
                "UPDATE approvals SET capability = ? WHERE approval_id = ?",
                (
                    Capability.DURABLE_MEMORY_PROMOTION.value,
                    active_approval.approval_id,
                ),
            )
        finally:
            connection.close()
            self.store.initialize()
        with self.assertRaisesRegex(IntegrityError, "event hash mismatch"):
            self.registry.get_active_rule_promotion_record(proposal.proposal_id)

    def test_active_readback_rejects_rehashed_approval_event_tamper_matrix(
        self,
    ) -> None:
        cases = (
            "capability",
            "decision",
            "project",
            "run",
            "requester",
            "approver",
            "action",
            "resource",
            "digest",
            "policy",
            "time",
        )
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                proposal, _, _, active_approval = self._active_fixture(
                    f"active-event-{index}"
                )

                def mutate(connection) -> None:
                    event = self._approval_event(
                        connection, active_approval.approval_id
                    )
                    payload_values = {
                        "capability": (
                            "capability",
                            Capability.DURABLE_MEMORY_PROMOTION.value,
                        ),
                        "decision": ("decision", "denied"),
                        "requester": (
                            "requester",
                            self.evaluator.principal_id,
                        ),
                        "action": ("action", "promote_improvement:limited"),
                        "resource": (
                            "resource",
                            "improvement://proposals/forgery",
                        ),
                        "digest": (
                            "request_digest",
                            content_hash({"forgery": "event-digest"}),
                        ),
                    }
                    if case in payload_values:
                        payload = json.loads(event["payload_json"])
                        field, value = payload_values[case]
                        payload[field] = value
                        connection.execute(
                            "UPDATE events SET payload_json = ? WHERE seq = ?",
                            (canonical_json(payload), event["seq"]),
                        )
                    else:
                        column, value = {
                            "project": ("project_id", "project-forgery"),
                            "run": ("run_id", "run-forgery"),
                            "approver": ("actor", self.evaluator.principal_id),
                            "policy": ("policy_version", "forged-policy"),
                            "time": (
                                "occurred_at",
                                "2000-01-01T00:00:00Z",
                            ),
                        }[case]
                        connection.execute(
                            f"UPDATE events SET {column} = ? WHERE seq = ?",
                            (value, event["seq"]),
                        )

                self._rewrite_event_history(mutate)
                self.assertEqual(
                    self.store.verify_event_chain(),
                    len(self.store.query("SELECT 1 FROM events")),
                )
                with self.assertRaises(IntegrityError):
                    self.registry.get_active_rule_promotion_record(proposal.proposal_id)

    def test_active_readback_rejects_rehashed_limited_authority_tamper_matrix(
        self,
    ) -> None:
        cases = (
            "approval_link",
            "promotion_record_link",
            "evidence_digest_claim",
            "limited_actor",
            "limited_project",
            "limited_run",
            "limited_policy",
            "limited_time",
            "approval_event_payload",
            "approval_event_sequence",
        )
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                proposal, limited_approval, _, active_approval = self._active_fixture(
                    f"limited-authority-{index}"
                )

                def mutate(connection) -> None:
                    limited_event = self._promotion_event(
                        connection, proposal.proposal_id, "limited"
                    )
                    approval_event = self._approval_event(
                        connection, limited_approval.approval_id
                    )
                    if case in {
                        "approval_link",
                        "promotion_record_link",
                        "evidence_digest_claim",
                    }:
                        payload = json.loads(limited_event["payload_json"])
                        if case == "approval_link":
                            payload["approval_id"] = active_approval.approval_id
                        elif case == "promotion_record_link":
                            payload["limited_rule_promotion_record"][
                                "promotion_record_id"
                            ] = "forged-limited-record"
                        else:
                            payload["limited_rule_promotion_record"]["request"][
                                "verification_evidence_digest"
                            ] = "b" * 64
                        connection.execute(
                            "UPDATE events SET payload_json = ? WHERE seq = ?",
                            (canonical_json(payload), limited_event["seq"]),
                        )
                    elif case == "approval_event_payload":
                        payload = json.loads(approval_event["payload_json"])
                        payload["decision"] = "denied"
                        connection.execute(
                            "UPDATE events SET payload_json = ? WHERE seq = ?",
                            (canonical_json(payload), approval_event["seq"]),
                        )
                    elif case == "approval_event_sequence":
                        connection.execute(
                            "UPDATE events SET seq = -1 WHERE seq = ?",
                            (approval_event["seq"],),
                        )
                        connection.execute(
                            "UPDATE events SET seq = ? WHERE seq = ?",
                            (approval_event["seq"], limited_event["seq"]),
                        )
                        connection.execute(
                            "UPDATE events SET seq = ? WHERE seq = -1",
                            (limited_event["seq"],),
                        )
                    else:
                        column, value = {
                            "limited_actor": (
                                "actor",
                                self.evaluator.principal_id,
                            ),
                            "limited_project": ("project_id", "project-forgery"),
                            "limited_run": ("run_id", "run-forgery"),
                            "limited_policy": (
                                "policy_version",
                                "forged-policy",
                            ),
                            "limited_time": (
                                "occurred_at",
                                "2000-01-01T00:00:00Z",
                            ),
                        }[case]
                        connection.execute(
                            f"UPDATE events SET {column} = ? WHERE seq = ?",
                            (value, limited_event["seq"]),
                        )

                self._rewrite_event_history(mutate)
                self.assertEqual(
                    self.store.verify_event_chain(),
                    len(self.store.query("SELECT 1 FROM events")),
                )
                with self.assertRaises(IntegrityError):
                    self.registry.get_active_rule_promotion_record(proposal.proposal_id)

    def test_active_promotion_persists_and_verifies_canonical_record(self) -> None:
        proposal = self._owner_review_proposal("canonical")
        heldout_id = proposal.held_out_eval_id
        limited_approval = self._approval(
            proposal, ProposalState.LIMITED, Capability.ACTIVE_RULE_PROMOTION
        )
        limited = self.registry.promote(
            proposal.proposal_id,
            target=ProposalState.LIMITED,
            approval_id=limited_approval.approval_id,
            actor=self.identities.owner,
            limited_request=self._limited_requests[proposal.proposal_id],
        )
        sealed = self._eval(
            limited,
            split="sealed",
            dataset="canonical-sealed",
            eval_id="eval-canonical-sealed",
        )
        limited = self.registry.attach_eval(
            proposal.proposal_id,
            sealed.eval_id,
            actor=self.identities.system,
        )
        custody = make_sealed_custody_attestation(
            proposal_id=proposal.proposal_id,
            eval_id=sealed.eval_id,
            project_id="project-1",
            candidate_digest=proposal.candidate_digest,
            dataset_digest=sealed.dataset_digest,
            eval_attestation_digest=sealed.attestation_digest,
            evaluator=self.evaluator,
        )
        self.registry.record_sealed_custody_attestation(
            proposal.proposal_id, attestation=custody
        )
        active_approval = self._approval(
            limited, ProposalState.ACTIVE, Capability.ACTIVE_RULE_PROMOTION
        )
        active = self.registry.promote(
            proposal.proposal_id,
            target=ProposalState.ACTIVE,
            approval_id=active_approval.approval_id,
            actor=self.identities.owner,
        )
        self.assertEqual(active.state, ProposalState.ACTIVE)

        record = self.registry.get_active_rule_promotion_record(proposal.proposal_id)
        self.assertIsInstance(record, ActiveRulePromotionRecord)
        self.assertEqual(record.candidate_id, proposal.proposal_id)
        self.assertEqual(record.candidate_digest, proposal.candidate_digest)
        self.assertEqual(record.policy_version, "companyos-policy-v1")
        self.assertEqual(record.promotion_validation_eval_id, heldout_id)
        self.assertEqual(record.promotion_validation_query_count, 1)
        self.assertEqual(record.promotion_validation_status, "pass")
        self.assertEqual(record.from_state, "limited")
        self.assertEqual(record.target_state, "active")
        self.assertEqual(record.sealed_eval_id, sealed.eval_id)
        self.assertEqual(record.sealed_dataset_use_count, 1)
        self.assertFalse(record.sealed_result_influenced_edits)
        self.assertEqual(record.safety_hard_failures, 0)
        self.assertEqual(record.eval_status, "pass")
        self.assertEqual(record.owner_approval_id, active_approval.approval_id)
        self.assertEqual(
            record.scope, "project://project-1/prompt_candidate/bounded-trial"
        )
        self.assertIn("public release", record.non_goals)
        self.assertEqual(record.actual_outcome, self.actual_outcome)
        self.assertEqual(record.actual_outcome_kind, "friction_reduction")
        self.assertEqual(record.source_task_id, "task-1")
        self.assertEqual(
            record.verification_evidence_id, self.source_evidence.evidence_id
        )
        self.assertEqual(record.sealed_custodian_id, "external-test-custodian")
        self.assertEqual(record.sealed_custody_provider, "test-only-custody-provider")
        self.assertEqual(len(record.sealed_custody_attestation_digest), 64)
        self.assertTrue(record.sealed_custody_verified_at.endswith("+00:00"))
        limited_record = self.registry.get_limited_rule_promotion_record(
            proposal.proposal_id
        )
        self.assertIsInstance(limited_record, LimitedRulePromotionRecord)
        self.assertEqual(
            record.limited_promotion_record_digest, limited_record.record_digest
        )
        self.assertEqual(
            len(
                {
                    record.proposal_maker_principal_id,
                    record.evaluator_principal_id,
                    record.sealed_custodian_id,
                    record.owner_principal_id,
                }
            ),
            4,
        )
        with self.assertRaises(FrozenInstanceError):
            record.scope = "tampered"  # type: ignore[misc]

        event = self.store.query(
            "SELECT payload_json FROM events WHERE aggregate_type = 'improvement' "
            "AND aggregate_id = ? AND event_type = 'improvement_promoted' "
            "ORDER BY seq DESC LIMIT 1",
            (proposal.proposal_id,),
        )[0]
        payload = json.loads(event["payload_json"])
        self.assertEqual(payload["active_rule_promotion_record"], record.to_dict())
        self.assertEqual(
            self.store.verify_event_chain(),
            len(self.store.query("SELECT 1 FROM events")),
        )

        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE improvement_proposals SET candidate_digest = ? "
                "WHERE proposal_id = ?",
                (content_hash({"tampered": True}), proposal.proposal_id),
            )
        with self.assertRaisesRegex(IntegrityError, "sealed evaluation"):
            self.registry.get_active_rule_promotion_record(proposal.proposal_id)


if __name__ == "__main__":
    unittest.main()
