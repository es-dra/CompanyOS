from __future__ import annotations

import json
import tempfile
import unittest
import uuid
from dataclasses import FrozenInstanceError, replace
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
    EvaluationRegistry,
)
from companyos_runtime.kernel import RuntimeKernel
from companyos_runtime.policy import PolicyEngine
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import (
    Capability,
    EvidenceState,
    GoalSpec,
    ProposalState,
    TaskSpec,
    canonical_json,
    content_hash,
)

from tests.evaluation_fixtures import (
    ExactTestEvalVerifier,
    make_eval_attestation,
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
            ),
            actor=self.identities.owner,
            idempotency_key="task-create",
        )
        self.registry = EvaluationRegistry(
            self.store, result_verifier=ExactTestEvalVerifier()
        )
        self.policy = PolicyEngine(self.store)

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

    def _approval(self, proposal, target: ProposalState, capability: Capability):
        digest = self.registry.promotion_request_digest(
            proposal.proposal_id, proposal.candidate_digest, target
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

    def _active_fixture(self, label: str):
        proposal = self._owner_review_proposal(label)
        limited_approval = self._approval(
            proposal, ProposalState.LIMITED, Capability.ACTIVE_RULE_PROMOTION
        )
        limited = self.registry.promote(
            proposal.proposal_id,
            target=ProposalState.LIMITED,
            approval_id=limited_approval.approval_id,
            actor=self.identities.owner,
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
            EvaluationRegistry(self.store).record_eval(
                **values,
                evaluator=self.evaluator,
                attestation=attestation,
            )
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
        with self.assertRaises(AuthorizationError):
            self.registry.promote(
                proposal.proposal_id,
                target=ProposalState.LIMITED,
                approval_id="missing-approval",
                actor=self.identities.owner,
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
            )

        limited_approval = self._approval(
            proposal, ProposalState.LIMITED, Capability.ACTIVE_RULE_PROMOTION
        )
        limited = self.registry.promote(
            proposal.proposal_id,
            target=ProposalState.LIMITED,
            approval_id=limited_approval.approval_id,
            actor=self.identities.owner,
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
        )
        with self.assertRaisesRegex(TransitionError, "after limited promotion"):
            self.registry.attach_eval(
                proposal.proposal_id,
                early_sealed.eval_id,
                actor=self.identities.system,
            )

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
            "eval_sequence_claim",
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
                        "eval_sequence_claim",
                    }:
                        payload = json.loads(limited_event["payload_json"])
                        if case == "approval_link":
                            payload["approval_id"] = active_approval.approval_id
                        elif case == "promotion_record_link":
                            payload["promotion_record_id"] = "forged-limited-record"
                        else:
                            payload["eval_event_seq"] += 1
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
        self.assertEqual(record.scope, proposal.editable_surface)
        self.assertIn("external_sealed_custody", record.non_goals)
        self.assertEqual(
            len(
                {
                    record.proposal_maker_principal_id,
                    record.evaluator_principal_id,
                    record.owner_principal_id,
                }
            ),
            3,
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
        with self.assertRaisesRegex(IntegrityError, "evaluation projections"):
            self.registry.get_active_rule_promotion_record(proposal.proposal_id)


if __name__ == "__main__":
    unittest.main()
