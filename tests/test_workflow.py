from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from companyos_runtime.adapters import AdapterReceipt
from companyos_runtime.errors import (
    AuthorizationError,
    ContractError,
    IntegrityError,
    SimulatedCrash,
)
from companyos_runtime.fake_provider import FakeProvider
from companyos_runtime.identity import Role
from companyos_runtime.kernel import RuntimeKernel
from companyos_runtime.leases import LeaseManager
from companyos_runtime.policy import PolicyEngine
from companyos_runtime.scheduler import TaskScheduler
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import (
    Capability,
    EvidenceState,
    GoalSpec,
    LoopEvent,
    TaskSpec,
    content_hash,
)
from companyos_runtime.workflow import DurableWorkflow

from tests.identity_fixtures import IdentityFixture


RESOURCE = "resource://one"
STEP_REQUESTS = {
    "before-effect": {"operation": "write", "case": "before-effect"},
    "stale-fence-after-consume": {
        "operation": "write",
        "case": "stale-fence-after-consume",
    },
    "after-effect": {"operation": "write", "case": "after-effect"},
    "after-checkpoint": {"operation": "write", "case": "after-checkpoint"},
    "failure": {
        "operation": "fail",
        "error_class": "SyntheticFailure",
        "message": "retain this deterministic failure",
    },
    "digest-mismatch": {"operation": "write", "value": "different"},
    "missing-grant": {"operation": "write", "value": "different"},
    "stale-fence": {"operation": "write", "case": "stale-fence"},
    "revoked-after-consume": {
        "operation": "write",
        "case": "revoked-after-consume",
    },
    "recovery-denied": {"operation": "write", "case": "recovery-denied"},
    "recovery-valid": {"operation": "write", "case": "recovery-valid"},
}


class DurableWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.store = SQLiteStore(root / "runtime.db")
        self.kernel = RuntimeKernel(self.store)
        self.kernel.initialize()
        self.identities = IdentityFixture(self.store)
        self.worker = self.identities.worker
        self.takeover_worker = self.identities.worker_named("takeover-worker")
        self.kernel.create_goal(
            project_id="project-1",
            spec=GoalSpec(
                goal_id="goal-1",
                target_outcome="exercise durable fake effect",
                success_evidence_states=(EvidenceState.RUNTIME,),
                allowed_capabilities=(Capability.WRITE_LOCAL,),
                write_scope=(RESOURCE,),
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
                objective="execute one idempotent fake effect",
                expected_delta="runtime",
                primary_surface=RESOURCE,
                evidence_target=EvidenceState.RUNTIME,
                capabilities=(Capability.WRITE_LOCAL,),
                write_scope=(RESOURCE,),
                workflow_steps=tuple(
                    {
                        "step_id": f"step-{name}",
                        "adapter": "fake-provider",
                        "action": "write",
                        "resource": RESOURCE,
                        "request_digest": content_hash(request),
                    }
                    for name, request in STEP_REQUESTS.items()
                ),
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
        task_claim = scheduler.claim_next(
            project_id="project-1", worker=self.worker, ttl_seconds=600
        )
        self.assertIsNotNone(task_claim)
        assert task_claim is not None
        self.provider = FakeProvider(root / "fake-provider.db")
        self.workflow = DurableWorkflow(self.store, self.provider)
        self.workflow.initialize()
        self.leases = LeaseManager(self.store)
        self.lease = self.leases.acquire(
            resource_key=RESOURCE,
            project_id="project-1",
            task_id="task-1",
            holder=self.worker,
            ttl_seconds=600,
        )
        self.kernel.advance_loop(
            run_id="run-1",
            event=LoopEvent.TASK_STARTED,
            actor=self.worker,
            idempotency_key="run-task-started",
            payload={
                "task_id": "task-1",
                "resource_key": RESOURCE,
                "holder": self.worker.principal_id,
                "fence": self.lease.fence,
            },
        )
        scheduler.start(task_claim, worker=self.worker)
        self.policy = PolicyEngine(self.store)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _grant(self, request: dict, *, max_uses: int = 1):
        digest = content_hash(request)
        approval = self.policy.record_approval(
            project_id="project-1",
            goal_id="goal-1",
            run_id="run-1",
            task_id="task-1",
            requester=self.worker,
            approver=self.identities.owner,
            capability=Capability.WRITE_LOCAL,
            action="write",
            resource=RESOURCE,
            request_digest=digest,
            policy_version="companyos-policy-v1",
            decision="approved",
            ttl_seconds=600,
        )
        return self.policy.issue_grant(
            approval_id=approval.approval_id,
            issuer=self.identities.owner,
            principal=self.worker,
            capability=Capability.WRITE_LOCAL,
            action="write",
            resource=RESOURCE,
            request_digest=digest,
            policy_version="companyos-policy-v1",
            ttl_seconds=300,
            max_uses=max_uses,
            required_fence=self.lease.fence,
        )

    def _enqueue(self, request: dict, grant_id: str, suffix: str):
        return self.workflow.enqueue(
            task_id="task-1",
            step_id=f"step-{suffix}",
            adapter="fake-provider",
            idempotency_key=f"provider-{suffix}",
            request=request,
            grant_id=grant_id,
            principal=self.worker,
            capability=Capability.WRITE_LOCAL,
            action="write",
            resource=RESOURCE,
            fence=self.lease.fence,
            effect_id=f"effect-{suffix}",
        )

    def test_crash_before_effect_recovers_with_exactly_one_external_effect(
        self,
    ) -> None:
        request = STEP_REQUESTS["before-effect"]
        grant = self._grant(request)
        effect = self._enqueue(request, grant.grant_id, "before-effect")

        with self.assertRaises(SimulatedCrash):
            self.workflow.dispatch(effect.effect_id, fault_at="before_effect")
        self.assertEqual(self.provider.effect_count(), 0)
        self.assertEqual(
            self.store.query(
                "SELECT status FROM outbox WHERE effect_id = ?", (effect.effect_id,)
            )[0]["status"],
            "ready",
        )

        recovered = self.workflow.recover_pending()
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].status, "succeeded")
        self.assertEqual(self.provider.effect_count(), 1)
        self.assertEqual(
            self.store.query(
                "SELECT used_count FROM capability_grants WHERE grant_id = ?",
                (grant.grant_id,),
            )[0]["used_count"],
            1,
        )

    def test_consumed_but_unexecuted_effect_revalidates_fence_without_revoke(
        self,
    ) -> None:
        request = STEP_REQUESTS["stale-fence-after-consume"]
        grant = self._grant(request)
        effect = self._enqueue(request, grant.grant_id, "stale-fence-after-consume")

        with self.assertRaises(SimulatedCrash):
            self.workflow.dispatch(effect.effect_id, fault_at="before_effect")
        self.leases.release(
            resource_key=RESOURCE,
            project_id="project-1",
            task_id="task-1",
            holder=self.worker,
            fence=self.lease.fence,
        )
        replacement = self.leases.acquire(
            resource_key=RESOURCE,
            project_id="project-1",
            task_id="task-1",
            holder=self.takeover_worker,
            ttl_seconds=600,
        )
        self.assertGreater(replacement.fence, self.lease.fence)

        recovered = self.workflow.recover_pending()
        self.assertEqual([item.status for item in recovered], ["failed"])
        self.assertEqual(recovered[0].result["authorization_outcome"], "denied")
        self.assertEqual(self.provider.effect_count(), 0)

    def test_crash_after_effect_before_checkpoint_reconciles_provider_receipt_once(
        self,
    ) -> None:
        request = STEP_REQUESTS["after-effect"]
        grant = self._grant(request)
        effect = self._enqueue(request, grant.grant_id, "after-effect")

        with self.assertRaises(SimulatedCrash):
            self.workflow.dispatch(
                effect.effect_id, fault_at="after_effect_before_checkpoint"
            )
        self.assertEqual(self.provider.effect_count(), 1)
        self.assertEqual(
            self.store.query("SELECT COUNT(*) AS count FROM effect_receipts")[0][
                "count"
            ],
            0,
        )

        recovered = self.workflow.recover_pending()
        self.assertEqual(len(recovered), 1)
        self.assertTrue(recovered[0].provider_replayed)
        self.assertFalse(recovered[0].checkpoint_replayed)
        self.assertEqual(self.provider.effect_count(), 1)
        self.assertEqual(
            self.store.query("SELECT COUNT(*) AS count FROM effect_receipts")[0][
                "count"
            ],
            1,
        )

    def test_crash_after_checkpoint_is_a_completed_noop_on_recovery(self) -> None:
        request = STEP_REQUESTS["after-checkpoint"]
        grant = self._grant(request)
        effect = self._enqueue(request, grant.grant_id, "after-checkpoint")

        with self.assertRaises(SimulatedCrash):
            self.workflow.dispatch(effect.effect_id, fault_at="after_checkpoint")
        self.assertEqual(self.provider.effect_count(), 1)
        self.assertEqual(self.workflow.recover_pending(), [])

        replay = self.workflow.dispatch(effect.effect_id)
        self.assertTrue(replay.provider_replayed)
        self.assertTrue(replay.checkpoint_replayed)
        self.assertEqual(self.provider.effect_count(), 1)
        stored_effect = self.workflow.get_effect(effect.effect_id)
        stored_receipt = self.workflow.get_receipt(effect.effect_id)
        self.assertEqual(stored_effect.status, "succeeded")
        self.assertNotIn("replayed", stored_effect.to_wire())
        self.assertIsNotNone(stored_receipt)
        assert stored_receipt is not None
        self.assertEqual(stored_receipt.effect_id, effect.effect_id)
        self.assertEqual(stored_receipt.result_digest, content_hash(replay.result))

    def test_provider_failure_is_checkpointed_and_retained_as_negative_result(
        self,
    ) -> None:
        request = STEP_REQUESTS["failure"]
        grant = self._grant(request)
        effect = self._enqueue(request, grant.grant_id, "failure")

        result = self.workflow.dispatch(effect.effect_id)
        self.assertEqual(result.status, "failed")
        failures = self.store.query(
            "SELECT * FROM negative_results WHERE task_id = ?", ("task-1",)
        )
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["failure_class"], "SyntheticFailure")
        self.assertEqual(failures[0]["recurrence_count"], 1)
        replay = self.workflow.dispatch(effect.effect_id)
        self.assertTrue(replay.checkpoint_replayed)
        self.assertEqual(self.provider.effect_count(), 1)
        self.assertEqual(
            self.store.query("SELECT recurrence_count FROM negative_results")[0][
                "recurrence_count"
            ],
            1,
        )

    def test_enqueue_rejects_invalid_authority_without_poisoning_declared_step(
        self,
    ) -> None:
        approved_request = {"operation": "write", "value": "approved"}
        actual_request = STEP_REQUESTS["digest-mismatch"]
        grant = self._grant(approved_request)
        with self.assertRaisesRegex(AuthorizationError, "exactly match"):
            self._enqueue(actual_request, grant.grant_id, "digest-mismatch")
        with self.assertRaisesRegex(AuthorizationError, "does not exist"):
            self._enqueue(actual_request, "missing-grant", "missing-grant")
        self.assertEqual(self.provider.effect_count(), 0)
        self.assertEqual(self.store.query("SELECT * FROM outbox"), [])
        self.assertEqual(self.store.query("SELECT * FROM workflow_steps"), [])

        valid_grant = self._grant(actual_request)
        corrected = self._enqueue(
            actual_request, valid_grant.grant_id, "digest-mismatch"
        )
        self.assertEqual(corrected.status, "authorization_pending")

    def test_non_holder_worker_cannot_enqueue_or_occupy_step(self) -> None:
        request = STEP_REQUESTS["digest-mismatch"]
        digest = content_hash(request)
        non_holder = self.identities.worker_named("non-holder-enqueuer")
        approval = self.policy.record_approval(
            project_id="project-1",
            goal_id="goal-1",
            run_id="run-1",
            task_id="task-1",
            requester=non_holder,
            approver=self.identities.owner,
            capability=Capability.WRITE_LOCAL,
            action="write",
            resource=RESOURCE,
            request_digest=digest,
            policy_version="companyos-policy-v1",
            decision="approved",
            ttl_seconds=600,
        )
        grant = self.policy.issue_grant(
            approval_id=approval.approval_id,
            issuer=self.identities.owner,
            principal=non_holder,
            capability=Capability.WRITE_LOCAL,
            action="write",
            resource=RESOURCE,
            request_digest=digest,
            policy_version="companyos-policy-v1",
            ttl_seconds=300,
        )
        with self.assertRaisesRegex(AuthorizationError, "no current task claim"):
            self.workflow.enqueue(
                task_id="task-1",
                step_id="step-digest-mismatch",
                adapter="fake-provider",
                idempotency_key="non-holder-enqueue",
                request=request,
                grant_id=grant.grant_id,
                principal=non_holder,
                capability=Capability.WRITE_LOCAL,
                action="write",
                resource=RESOURCE,
                fence=None,
                effect_id="effect-non-holder",
            )
        self.assertEqual(self.store.query("SELECT * FROM outbox"), [])
        self.assertEqual(self.store.query("SELECT * FROM workflow_steps"), [])

    def test_stale_lease_fence_cannot_dispatch_an_enqueued_effect(self) -> None:
        request = STEP_REQUESTS["stale-fence"]
        grant = self._grant(request)
        effect = self._enqueue(request, grant.grant_id, "stale-fence")
        self.leases.release(
            resource_key=RESOURCE,
            project_id="project-1",
            task_id="task-1",
            holder=self.worker,
            fence=self.lease.fence,
        )
        replacement = self.leases.acquire(
            resource_key=RESOURCE,
            project_id="project-1",
            task_id="task-1",
            holder=self.takeover_worker,
            ttl_seconds=600,
        )
        self.assertGreater(replacement.fence, self.lease.fence)

        with self.assertRaises(AuthorizationError):
            self.workflow.dispatch(effect.effect_id)
        self.assertEqual(self.provider.effect_count(), 0)

    def test_consumed_but_unexecuted_effect_revalidates_revocation_and_fence(
        self,
    ) -> None:
        request = STEP_REQUESTS["revoked-after-consume"]
        grant = self._grant(request)
        effect = self._enqueue(request, grant.grant_id, "revoked-after-consume")

        with self.assertRaises(SimulatedCrash):
            self.workflow.dispatch(effect.effect_id, fault_at="before_effect")
        self.assertEqual(self.provider.effect_count(), 0)
        self.assertEqual(
            self.store.query(
                "SELECT used_count FROM capability_grants WHERE grant_id = ?",
                (grant.grant_id,),
            )[0]["used_count"],
            1,
        )

        self.policy.revoke_grant(grant.grant_id, actor=self.identities.owner)
        self.leases.release(
            resource_key=RESOURCE,
            project_id="project-1",
            task_id="task-1",
            holder=self.worker,
            fence=self.lease.fence,
        )
        replacement = self.leases.acquire(
            resource_key=RESOURCE,
            project_id="project-1",
            task_id="task-1",
            holder=self.takeover_worker,
            ttl_seconds=600,
        )
        self.assertGreater(replacement.fence, self.lease.fence)

        recovered = self.workflow.recover_pending()
        self.assertEqual([item.status for item in recovered], ["failed"])
        self.assertEqual(recovered[0].result["authorization_outcome"], "denied")
        self.assertEqual(self.provider.effect_count(), 0)
        self.assertEqual(
            self.store.query(
                "SELECT status FROM outbox WHERE effect_id = ?", (effect.effect_id,)
            )[0]["status"],
            "failed",
        )

    def test_enqueue_requires_exact_declared_workflow_step_binding(self) -> None:
        request = STEP_REQUESTS["before-effect"]
        grant = self._grant(request, max_uses=5)
        base = {
            "task_id": "task-1",
            "step_id": "step-before-effect",
            "adapter": "fake-provider",
            "request": request,
            "grant_id": grant.grant_id,
            "principal": self.worker,
            "capability": Capability.WRITE_LOCAL,
            "action": "write",
            "resource": RESOURCE,
            "fence": self.lease.fence,
        }
        cases = (
            {"step_id": "step-undeclared"},
            {"adapter": "different-adapter"},
            {"action": "different-action"},
            {"resource": "resource://different"},
            {"request": {"operation": "write", "case": "different"}},
        )
        for index, override in enumerate(cases):
            with self.subTest(override=override):
                with self.assertRaisesRegex(ContractError, "workflow step|binding"):
                    self.workflow.enqueue(
                        **(base | override),
                        idempotency_key=f"binding-denied-{index}",
                        effect_id=f"binding-denied-{index}",
                    )
        self.assertEqual(
            self.store.query("SELECT COUNT(*) AS count FROM outbox")[0]["count"],
            0,
        )

    def test_dispatch_rechecks_exact_step_binding_before_external_effect(self) -> None:
        request = STEP_REQUESTS["before-effect"]
        grant = self._grant(request)
        effect = self._enqueue(request, grant.grant_id, "before-effect")
        task = self.store.query(
            "SELECT spec_json FROM tasks WHERE task_id = ?", ("task-1",)
        )[0]
        spec = json.loads(task["spec_json"])
        target = next(
            step
            for step in spec["workflow_steps"]
            if step["step_id"] == "step-before-effect"
        )
        target["adapter"] = "tampered-adapter"
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE tasks SET spec_json = ? WHERE task_id = ?",
                (json.dumps(spec, sort_keys=True), "task-1"),
            )

        with self.assertRaisesRegex(ContractError, "binding"):
            self.workflow.dispatch(effect.effect_id)

        self.assertEqual(self.provider.effect_count(), 0)
        usage = self.store.query(
            "SELECT used_count FROM capability_grants WHERE grant_id = ?",
            (grant.grant_id,),
        )[0]
        self.assertEqual(usage["used_count"], 0)

    def test_recovery_persists_denial_and_continues_to_later_valid_effect(
        self,
    ) -> None:
        denied = STEP_REQUESTS["recovery-denied"]
        valid = STEP_REQUESTS["recovery-valid"]
        denied_grant = self._grant(denied)
        self._enqueue(denied, denied_grant.grant_id, "recovery-denied")
        self.policy.revoke_grant(denied_grant.grant_id, actor=self.identities.owner)
        valid_grant = self._grant(valid)
        self._enqueue(valid, valid_grant.grant_id, "recovery-valid")

        recovered = self.workflow.recover_pending()

        self.assertEqual([item.status for item in recovered], ["failed", "succeeded"])
        self.assertEqual(recovered[0].result["authorization_outcome"], "denied")
        self.assertEqual(self.provider.effect_count(), 1)
        statuses = {
            row["effect_id"]: row["status"]
            for row in self.store.query("SELECT effect_id, status FROM outbox")
        }
        self.assertEqual(statuses["effect-recovery-denied"], "failed")
        self.assertEqual(statuses["effect-recovery-valid"], "succeeded")
        negative = self.store.query(
            "SELECT failure_class, repair_route FROM negative_results "
            "WHERE task_id = ?",
            ("task-1",),
        )
        self.assertEqual(len(negative), 1)
        self.assertEqual(negative[0]["failure_class"], "AuthorizationError")
        self.assertEqual(
            negative[0]["repair_route"], "inspect_effect_authorization_failure"
        )

    def test_role_removal_denial_does_not_starve_later_valid_effect(self) -> None:
        denied_request = STEP_REQUESTS["recovery-denied"]
        valid_request = STEP_REQUESTS["recovery-valid"]

        def grant_for(request: dict, principal):
            digest = content_hash(request)
            approval = self.policy.record_approval(
                project_id="project-1",
                goal_id="goal-1",
                run_id="run-1",
                task_id="task-1",
                requester=principal,
                approver=self.identities.owner,
                capability=Capability.WRITE_LOCAL,
                action="write",
                resource=RESOURCE,
                request_digest=digest,
                policy_version="companyos-policy-v1",
                decision="approved",
                ttl_seconds=600,
            )
            return self.policy.issue_grant(
                approval_id=approval.approval_id,
                issuer=self.identities.owner,
                principal=principal,
                capability=Capability.WRITE_LOCAL,
                action="write",
                resource=RESOURCE,
                request_digest=digest,
                policy_version="companyos-policy-v1",
                ttl_seconds=300,
            )

        denied_grant = grant_for(denied_request, self.worker)
        valid_worker = self.identities.worker_named("role-valid-worker")
        valid_grant = grant_for(valid_request, valid_worker)
        self.workflow.enqueue(
            task_id="task-1",
            step_id="step-recovery-denied",
            adapter="fake-provider",
            idempotency_key="role-denied-effect",
            request=denied_request,
            grant_id=denied_grant.grant_id,
            principal=self.worker,
            capability=Capability.WRITE_LOCAL,
            action="write",
            resource=RESOURCE,
            fence=None,
            effect_id="effect-role-denied",
        )
        task_claim = self.store.query(
            "SELECT fence FROM leases WHERE resource_key = 'task://task-1'"
        )[0]
        self.leases.release(
            resource_key="task://task-1",
            project_id="project-1",
            task_id="task-1",
            holder=self.worker,
            fence=int(task_claim["fence"]),
        )
        self.leases.acquire(
            resource_key="task://task-1",
            project_id="project-1",
            task_id="task-1",
            holder=valid_worker,
            ttl_seconds=600,
        )
        self.workflow.enqueue(
            task_id="task-1",
            step_id="step-recovery-valid",
            adapter="fake-provider",
            idempotency_key="role-valid-effect",
            request=valid_request,
            grant_id=valid_grant.grant_id,
            principal=valid_worker,
            capability=Capability.WRITE_LOCAL,
            action="write",
            resource=RESOURCE,
            fence=None,
            effect_id="effect-role-valid",
        )
        self.identities.manager.set_roles(
            self.identities.owner,
            display_name="test-worker",
            roles={Role.OBSERVER},
        )

        recovered = self.workflow.recover_pending()
        self.assertEqual(
            [(item.effect_id, item.status) for item in recovered],
            [("effect-role-denied", "failed"), ("effect-role-valid", "succeeded")],
        )
        self.assertEqual(self.provider.effect_count(), 1)

    def test_terminal_task_seals_pending_effect_without_provider_call(self) -> None:
        request = STEP_REQUESTS["before-effect"]
        grant = self._grant(request)
        effect = self._enqueue(request, grant.grant_id, "before-effect")
        self.kernel.control_task(
            task_id="task-1",
            action="block",
            reason="owner stopped execution before dispatch",
            actor=self.identities.owner,
            idempotency_key="block-before-dispatch",
        )
        self.kernel.control_task(
            task_id="task-1",
            action="cancel",
            reason="owner sealed the task before dispatch",
            actor=self.identities.owner,
            idempotency_key="cancel-before-dispatch",
        )

        recovered = self.workflow.recover_pending()
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].effect_id, effect.effect_id)
        self.assertEqual(recovered[0].status, "failed")
        self.assertEqual(self.provider.effect_count(), 0)
        negative = self.store.query(
            "SELECT failure_class, repair_route FROM negative_results "
            "WHERE task_id = ?",
            ("task-1",),
        )
        self.assertEqual(len(negative), 1)
        self.assertEqual(negative[0]["failure_class"], "AuthorizationError")
        self.assertEqual(
            negative[0]["repair_route"], "inspect_effect_authorization_failure"
        )

    def test_expired_task_claim_blocks_unfenced_pending_effect(self) -> None:
        request = STEP_REQUESTS["before-effect"]
        digest = content_hash(request)
        approval = self.policy.record_approval(
            project_id="project-1",
            goal_id="goal-1",
            run_id="run-1",
            task_id="task-1",
            requester=self.worker,
            approver=self.identities.owner,
            capability=Capability.WRITE_LOCAL,
            action="write",
            resource=RESOURCE,
            request_digest=digest,
            policy_version="companyos-policy-v1",
            decision="approved",
            ttl_seconds=600,
        )
        grant = self.policy.issue_grant(
            approval_id=approval.approval_id,
            issuer=self.identities.owner,
            principal=self.worker,
            capability=Capability.WRITE_LOCAL,
            action="write",
            resource=RESOURCE,
            request_digest=digest,
            policy_version="companyos-policy-v1",
            ttl_seconds=300,
        )
        effect = self.workflow.enqueue(
            task_id="task-1",
            step_id="step-before-effect",
            adapter="fake-provider",
            idempotency_key="expired-task-claim-effect",
            request=request,
            grant_id=grant.grant_id,
            principal=self.worker,
            capability=Capability.WRITE_LOCAL,
            action="write",
            resource=RESOURCE,
            fence=None,
            effect_id="effect-expired-task-claim",
        )
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE leases SET issued_at = '1999-12-31T23:59:00.000Z', "
                "expires_at = '2000-01-01T00:00:00.000Z' "
                "WHERE resource_key = 'task://task-1'"
            )

        recovered = self.workflow.recover_pending()
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].effect_id, effect.effect_id)
        self.assertEqual(recovered[0].status, "failed")
        self.assertIn("no current task claim", recovered[0].result["message"])
        self.assertEqual(self.provider.effect_count(), 0)

    def test_fake_provider_idempotency_is_project_scoped(self) -> None:
        request = {"operation": "write", "case": "project-scoped"}
        digest = content_hash(request)
        first = self.provider.execute(
            project_id="project-one",
            idempotency_key="shared-key",
            effect_id="effect-one",
            request_digest=digest,
            request=request,
        )
        second = self.provider.execute(
            project_id="project-two",
            idempotency_key="shared-key",
            effect_id="effect-two",
            request_digest=digest,
            request=request,
        )

        self.assertNotEqual(first.provider_receipt, second.provider_receipt)
        self.assertEqual(self.provider.effect_count(), 2)
        self.assertEqual(self.provider.effect_count(project_id="project-one"), 1)

    def test_dispatch_consumes_authority_before_adapter_lookup(self) -> None:
        class LookupCountingProvider(FakeProvider):
            def __init__(self, path):
                super().__init__(path)
                self.lookup_count = 0

            def lookup(self, **kwargs):
                self.lookup_count += 1
                return super().lookup(**kwargs)

        request = STEP_REQUESTS["stale-fence"]
        grant = self._grant(request)
        effect = self._enqueue(request, grant.grant_id, "stale-fence")
        self.leases.release(
            resource_key=RESOURCE,
            project_id="project-1",
            task_id="task-1",
            holder=self.worker,
            fence=self.lease.fence,
        )
        provider = LookupCountingProvider(self.provider.path)
        provider.initialize()
        self.workflow.provider = provider

        with self.assertRaises(AuthorizationError):
            self.workflow.dispatch(effect.effect_id)
        self.assertEqual(provider.lookup_count, 0)

    def test_dispatch_verifies_persisted_step_before_adapter_lookup(self) -> None:
        class LookupCountingProvider(FakeProvider):
            def __init__(self, path):
                super().__init__(path)
                self.lookup_count = 0

            def lookup(self, **kwargs):
                self.lookup_count += 1
                return super().lookup(**kwargs)

        request = STEP_REQUESTS["before-effect"]
        grant = self._grant(request)
        effect = self._enqueue(request, grant.grant_id, "before-effect")
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "DELETE FROM workflow_steps WHERE task_id = ? AND step_id = ?",
                ("task-1", "step-before-effect"),
            )
        provider = LookupCountingProvider(self.provider.path)
        provider.initialize()
        self.workflow.provider = provider

        with self.assertRaisesRegex(IntegrityError, "missing persisted workflow step"):
            self.workflow.dispatch(effect.effect_id)
        self.assertEqual(provider.lookup_count, 0)

    def test_dispatch_rejects_receipt_with_mismatched_identity(self) -> None:
        class ForgedReceiptProvider(FakeProvider):
            def execute(self, **kwargs):
                receipt = super().execute(**kwargs)
                return AdapterReceipt(
                    adapter_id=receipt.adapter_id,
                    project_id="another-project",
                    idempotency_key=receipt.idempotency_key,
                    effect_id=receipt.effect_id,
                    request_digest=receipt.request_digest,
                    provider_receipt=receipt.provider_receipt,
                    status=receipt.status,
                    closed=receipt.closed,
                    result=receipt.result,
                    replayed=receipt.replayed,
                )

        request = STEP_REQUESTS["before-effect"]
        grant = self._grant(request)
        effect = self._enqueue(request, grant.grant_id, "before-effect")
        provider = ForgedReceiptProvider(self.provider.path)
        provider.initialize()
        self.workflow.provider = provider

        with self.assertRaisesRegex(IntegrityError, "receipt identity"):
            self.workflow.dispatch(effect.effect_id)
        self.assertIsNone(self.workflow.get_receipt(effect.effect_id))

    def test_fake_provider_migrates_legacy_global_idempotency_safely(self) -> None:
        path = Path(self.temp.name) / "legacy-provider.db"
        request = {"operation": "write", "case": "legacy"}
        digest = content_hash(request)
        connection = sqlite3.connect(path)
        try:
            connection.execute(
                """
                CREATE TABLE provider_effects(
                    idempotency_key TEXT PRIMARY KEY,
                    effect_id TEXT NOT NULL UNIQUE,
                    request_digest TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    provider_receipt TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "INSERT INTO provider_effects VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "legacy-key",
                    "legacy-effect",
                    digest,
                    json.dumps(request),
                    "legacy-receipt",
                    "succeeded",
                    json.dumps({"accepted": True}),
                    "2026-01-01T00:00:00Z",
                ),
            )
            connection.commit()
        finally:
            connection.close()

        migrated = FakeProvider(path)
        migrated.initialize()
        replay = migrated.lookup(
            project_id="project-new",
            idempotency_key="legacy-key",
            effect_id="legacy-effect",
            request_digest=digest,
        )

        self.assertIsNone(replay)
        explicitly_migrated = FakeProvider(
            path, legacy_project_migrations={"legacy-key": "project-new"}
        )
        explicitly_migrated.initialize()
        replay = explicitly_migrated.lookup(
            project_id="project-new",
            idempotency_key="legacy-key",
            effect_id="legacy-effect",
            request_digest=digest,
        )
        self.assertIsNotNone(replay)
        assert replay is not None
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.provider_receipt, "legacy-receipt")
        connection = migrated.connect()
        try:
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(provider_effects)")
            }
        finally:
            connection.close()
        self.assertIn("project_id", columns)


if __name__ == "__main__":
    unittest.main()
