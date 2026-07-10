from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

from companyos_runtime.errors import AuthorizationError
from companyos_runtime.identity import IdentityManager, Role, VerifiedPrincipal
from companyos_runtime.leases import LeaseManager
from companyos_runtime.policy import PolicyEngine
from companyos_runtime.store import SQLiteStore
from companyos_runtime.types import (
    Capability,
    GoalSpec,
    TaskSpec,
    canonical_json,
    content_hash,
    utc_now,
)

from tests.identity_fixtures import IdentityFixture


class PolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "runtime.db")
        self.store.initialize()
        self.identities = IdentityFixture(self.store)
        self._seed_scope()
        self.task_claim_lease = LeaseManager(self.store).acquire(
            resource_key="task://task-1",
            project_id="project-1",
            task_id="task-1",
            holder=self.identities.worker,
            ttl_seconds=600,
        )
        self.policy = PolicyEngine(self.store)
        self.digest = content_hash({"operation": "write", "value": 1})

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _seed_scope(self) -> None:
        now = utc_now()
        goal = GoalSpec.from_dict(
            {
                "goal_id": "goal-1",
                "target_outcome": "exercise bounded policy",
                "success_evidence_states": ["runtime_verification"],
                "write_scope": [
                    "resource://one",
                    "memory://memory-1",
                    "provider://fake",
                ],
                "allowed_capabilities": [
                    "write_local",
                    "provider_cost",
                    "durable_memory_promotion",
                ],
                "provider_budget_minor_units": 100,
                "provider_call_limit": 3,
                "budget_currency": "USD",
            }
        )
        task = TaskSpec.from_dict(
            {
                "task_id": "task-1",
                "goal_id": "goal-1",
                "objective": "exercise bounded policy",
                "expected_delta": "quality",
                "primary_surface": "policy",
                "evidence_target": "runtime_verification",
                "write_scope": [
                    "resource://one",
                    "memory://memory-1",
                    "provider://fake",
                ],
                "capabilities": [
                    "write_local",
                    "provider_cost",
                    "durable_memory_promotion",
                ],
            }
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
                (
                    "run-1",
                    "goal-1",
                    "project-1",
                    "running",
                    "policy-v1",
                    1,
                    now,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO tasks(
                    task_id, goal_id, run_id, project_id, state, spec_json,
                    aggregate_version, attempt_count, due_at,
                    last_error_fingerprint, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                """,
                (
                    "task-1",
                    "goal-1",
                    "run-1",
                    "project-1",
                    "running",
                    canonical_json(task.to_dict()),
                    1,
                    0,
                    now,
                    now,
                ),
            )

    def _approval(
        self,
        *,
        decision: str = "approved",
        capability: Capability = Capability.WRITE_LOCAL,
        action: str = "write",
        resource: str = "resource://one",
        digest: str | None = None,
        requester: VerifiedPrincipal | None = None,
    ):
        requester = requester or self.identities.worker
        return self.policy.record_approval(
            project_id="project-1",
            goal_id="goal-1",
            run_id="run-1",
            task_id="task-1",
            requester=requester,
            approver=self.identities.owner,
            capability=capability,
            action=action,
            resource=resource,
            request_digest=digest or self.digest,
            policy_version="policy-v1",
            decision=decision,
            ttl_seconds=600,
        )

    def _grant(
        self,
        *,
        capability: Capability = Capability.WRITE_LOCAL,
        action: str = "write",
        resource: str = "resource://one",
        digest: str | None = None,
        max_uses: int = 1,
        cost_limit: int = 0,
        required_fence: int | None = None,
        requester: VerifiedPrincipal | None = None,
    ):
        requester = requester or self.identities.worker
        digest = digest or self.digest
        approval = self._approval(
            capability=capability,
            action=action,
            resource=resource,
            digest=digest,
            requester=requester,
        )
        return self.policy.issue_grant(
            approval_id=approval.approval_id,
            issuer=self.identities.owner,
            principal=requester,
            capability=capability,
            action=action,
            resource=resource,
            request_digest=digest,
            policy_version="policy-v1",
            ttl_seconds=300,
            max_uses=max_uses,
            cost_limit=cost_limit,
            required_fence=required_fence,
        )

    def _consume(
        self,
        grant_id: str,
        *,
        project_id: str = "project-1",
        goal_id: str = "goal-1",
        run_id: str = "run-1",
        task_id: str = "task-1",
        principal: VerifiedPrincipal | None = None,
        capability: Capability = Capability.WRITE_LOCAL,
        action: str = "write",
        resource: str = "resource://one",
        request_digest: str | None = None,
        idempotency_key: str = "use-1",
        cost: int = 0,
        fence: int | None = None,
        effect_id: str | None = None,
    ):
        return self.policy.consume(
            grant_id,
            project_id=project_id,
            goal_id=goal_id,
            run_id=run_id,
            task_id=task_id,
            principal=principal or self.identities.worker,
            capability=capability,
            action=action,
            resource=resource,
            request_digest=request_digest or self.digest,
            idempotency_key=idempotency_key,
            cost=cost,
            fence=fence,
            effect_id=effect_id,
        )

    def _rewrite_task_contract(self, **overrides: Any) -> TaskSpec:
        row = self.store.query(
            "SELECT spec_json FROM tasks WHERE task_id = ?", ("task-1",)
        )[0]
        values = json.loads(row["spec_json"])
        values.update(overrides)
        spec = TaskSpec.from_dict(values)
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE tasks SET spec_json = ? WHERE task_id = ?",
                (canonical_json(spec.to_dict()), "task-1"),
            )
        return spec

    def _rewrite_goal_contract(self, **overrides: Any) -> GoalSpec:
        row = self.store.query(
            "SELECT spec_json FROM goals WHERE goal_id = ?", ("goal-1",)
        )[0]
        values = json.loads(row["spec_json"])
        values.update(overrides)
        spec = GoalSpec.from_dict(values)
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE goals SET spec_json = ? WHERE goal_id = ?",
                (canonical_json(spec.to_dict()), "goal-1"),
            )
        return spec

    def _rewrite_lifecycle(self, *, run_state: str, task_state: str) -> None:
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE runs SET loop_state = ? WHERE run_id = 'run-1'",
                (run_state,),
            )
            connection.execute(
                "UPDATE tasks SET state = ? WHERE task_id = 'task-1'",
                (task_state,),
            )

    def test_grant_is_exactly_bound_and_fails_closed(self) -> None:
        grant = self._grant()
        invalid_requests: tuple[dict[str, Any], ...] = (
            {"project_id": "project-other"},
            {"goal_id": "goal-other"},
            {"run_id": "run-other"},
            {"task_id": "task-other"},
            {"capability": Capability.SERVER_WRITE},
            {"action": "delete"},
            {"resource": "resource://other"},
            {"request_digest": content_hash({"operation": "other"})},
        )
        for override in invalid_requests:
            with self.subTest(override=override):
                with self.assertRaises(AuthorizationError):
                    self._consume(grant.grant_id, **override)

        with self.assertRaisesRegex(AuthorizationError, "authenticated session"):
            self._consume(
                grant.grant_id,
                principal="worker-forgery",  # type: ignore[arg-type]
            )

        used = self._consume(grant.grant_id)
        self.assertFalse(used.replayed)
        self.assertEqual(used.used_count, 1)
        self.assertEqual(used.cost_used, 0)
        with self.assertRaises(AuthorizationError):
            self._consume(grant.grant_id, idempotency_key="use-2", cost=0)

    def test_capability_action_resource_mapping_is_fail_closed(self) -> None:
        all_capabilities = [item.value for item in Capability]
        read_scope = [
            "read://allowed/public/**",
            "network://read",
            "download://trusted",
            "server://readonly",
        ]
        write_scope = [
            "write://allowed",
            "network://write",
            "repo://companyos",
            "server://staging",
            "provider://fake",
            "release://staging",
            "destructive://scratch",
            "memory://memory-1",
            "rule://rule-1",
            "control://run-1",
        ]
        self._rewrite_goal_contract(
            allowed_capabilities=all_capabilities,
            read_scope=read_scope,
            write_scope=write_scope,
        )
        self._rewrite_task_contract(
            capabilities=all_capabilities,
            read_scope=read_scope,
            write_scope=write_scope,
            forbidden_scope=[
                "read://allowed/secret/**",
                "server://production/**",
                "provider://paid/**",
                "repo://unrelated/**",
            ],
        )

        allowed = (
            (Capability.READ_LOCAL, "read", "read://allowed/public/file"),
            (Capability.NETWORK, "get", "network://read/api"),
            (Capability.NETWORK, "post", "network://write/api"),
            (
                Capability.EXTERNAL_DOWNLOAD,
                "download",
                "download://trusted/archive",
            ),
            (Capability.REPO_REMOTE, "push", "repo://companyos/branch"),
            (Capability.SERVER_READ, "probe", "server://readonly/health"),
            (Capability.SERVER_WRITE, "restart", "server://staging/service"),
            (Capability.PROVIDER_COST, "invoke", "provider://fake/model"),
            (Capability.PUBLIC_RELEASE, "publish", "release://staging/v1"),
            (Capability.DESTRUCTIVE, "delete", "destructive://scratch/file"),
            (
                Capability.DURABLE_MEMORY_PROMOTION,
                "promote_memory",
                "memory://memory-1",
            ),
            (
                Capability.ACTIVE_RULE_PROMOTION,
                "promote_improvement:active",
                "rule://rule-1",
            ),
        )
        for capability, action, resource in allowed:
            with self.subTest(allowed=(capability, action, resource)):
                approval = self._approval(
                    capability=capability,
                    action=action,
                    resource=resource,
                )
                self.assertEqual(approval.resource, resource)

        rejected = (
            (
                Capability.READ_LOCAL,
                "delete",
                "read://allowed/public/file",
                "not allowed",
            ),
            (
                Capability.SERVER_READ,
                "restart",
                "server://readonly/health",
                "not allowed",
            ),
            (
                Capability.WRITE_LOCAL,
                "execute",
                "write://allowed/file",
                "not allowed",
            ),
            (
                Capability.NETWORK,
                "delete",
                "network://write/api",
                "no fail-closed scope mapping",
            ),
            (Capability.READ_LOCAL, "read", "write://allowed/file", "read_scope"),
            (
                Capability.WRITE_LOCAL,
                "write",
                "read://allowed/file",
                "write_scope",
            ),
            (
                Capability.READ_LOCAL,
                "read",
                "read://allowed/secret/token",
                "forbids resource",
            ),
            (
                Capability.SERVER_WRITE,
                "restart",
                "server://production/api",
                "forbids resource",
            ),
            (
                Capability.PROVIDER_COST,
                "invoke",
                "provider://paid/model",
                "forbids resource",
            ),
            (
                Capability.REPO_REMOTE,
                "push",
                "repo://unrelated/main",
                "forbids resource",
            ),
            (
                Capability.NETWORK,
                "unclassified-tunnel",
                "network://write/api",
                "no fail-closed scope mapping",
            ),
        )
        for capability, action, resource, message in rejected:
            with self.subTest(rejected=(capability, action, resource)):
                with self.assertRaisesRegex(AuthorizationError, message):
                    self._approval(
                        capability=capability,
                        action=action,
                        resource=resource,
                    )

    def test_issue_and_consume_revalidate_current_task_resource_scope(self) -> None:
        approval = self._approval()
        self._rewrite_task_contract(write_scope=["resource://other"])
        with self.assertRaisesRegex(AuthorizationError, "compiled authority"):
            self.policy.issue_grant(
                approval_id=approval.approval_id,
                issuer=self.identities.owner,
                principal=self.identities.worker,
                capability=Capability.WRITE_LOCAL,
                action="write",
                resource="resource://one",
                request_digest=self.digest,
                policy_version="policy-v1",
                ttl_seconds=300,
            )

        self._rewrite_task_contract(write_scope=["resource://one"], forbidden_scope=[])
        grant = self._grant()
        self._rewrite_task_contract(
            write_scope=["resource://one"],
            forbidden_scope=["resource://one/**"],
        )
        with self.assertRaisesRegex(AuthorizationError, "compiled authority"):
            self._consume(grant.grant_id)

        row = self.store.query(
            "SELECT used_count FROM capability_grants WHERE grant_id = ?",
            (grant.grant_id,),
        )[0]
        self.assertEqual(row["used_count"], 0)

    def test_policy_rejects_task_projection_expanded_beyond_parent_goal(self) -> None:
        self._rewrite_task_contract(write_scope=["resource://outside-goal"])
        with self.assertRaisesRegex(AuthorizationError, "compiled authority"):
            self._approval(resource="resource://outside-goal")

    def test_consume_requires_execution_phase_and_terminal_is_sealed(self) -> None:
        grant = self._grant()
        self._rewrite_lifecycle(run_state="ready", task_state="ready")
        with self.assertRaisesRegex(AuthorizationError, "not executable"):
            self._consume(grant.grant_id)
        self.assertEqual(
            self.store.query(
                "SELECT used_count FROM capability_grants WHERE grant_id = ?",
                (grant.grant_id,),
            )[0]["used_count"],
            0,
        )
        self._rewrite_lifecycle(run_state="delivered", task_state="delivered")
        with self.assertRaisesRegex(AuthorizationError, "sealed|not executable"):
            self._approval()

    def test_canceled_task_cannot_back_active_promotion_approval(self) -> None:
        self._rewrite_goal_contract(
            allowed_capabilities=[Capability.ACTIVE_RULE_PROMOTION.value],
            write_scope=["improvement://proposals/proposal-1"],
        )
        self._rewrite_task_contract(
            capabilities=[Capability.ACTIVE_RULE_PROMOTION.value],
            write_scope=["improvement://proposals/proposal-1"],
        )
        self._rewrite_lifecycle(run_state="delivered", task_state="canceled")
        with self.assertRaisesRegex(AuthorizationError, "cannot authorize promotion"):
            self._approval(
                capability=Capability.ACTIVE_RULE_PROMOTION,
                action="promote_improvement:active",
                resource="improvement://proposals/proposal-1",
            )

    def test_disable_cannot_commit_between_authentication_and_consumption(
        self,
    ) -> None:
        grant = self._grant()
        authenticated = threading.Event()
        release_consume = threading.Event()
        disable_attempted = threading.Event()
        disable_transaction_acquired = threading.Event()
        results: list[Any] = []
        errors: list[Exception] = []
        worker = self.identities.worker

        class HookedIdentityManager(IdentityManager):
            def verify(self, session: VerifiedPrincipal):
                record = super().verify(session)
                if session is worker:
                    authenticated.set()
                    release_consume.wait(timeout=5)
                return record

            def verify_in_transaction(self, connection, session):
                record = super().verify_in_transaction(connection, session)
                if session is worker:
                    authenticated.set()
                    release_consume.wait(timeout=5)
                return record

        self.policy.identity = HookedIdentityManager(self.store)

        def consume() -> None:
            try:
                results.append(self._consume(grant.grant_id))
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        def disable() -> None:
            disable_attempted.set()
            with self.store.transaction(immediate=True) as connection:
                disable_transaction_acquired.set()
                now = utc_now()
                connection.execute(
                    "UPDATE principals SET enabled = 0, disabled_at = ?, "
                    "updated_at = ? WHERE principal_id = ?",
                    (now, now, worker.principal_id),
                )
                connection.execute(
                    "UPDATE authenticated_sessions SET revoked_at = ? "
                    "WHERE principal_id = ? AND revoked_at IS NULL",
                    (now, worker.principal_id),
                )

        consume_thread = threading.Thread(target=consume)
        consume_thread.start()
        self.assertTrue(authenticated.wait(timeout=5))
        disable_thread = threading.Thread(target=disable)
        disable_thread.start()
        self.assertTrue(disable_attempted.wait(timeout=5))
        self.assertFalse(disable_transaction_acquired.wait(timeout=0.25))

        release_consume.set()
        consume_thread.join(timeout=5)
        disable_thread.join(timeout=5)

        self.assertFalse(consume_thread.is_alive())
        self.assertFalse(disable_thread.is_alive())
        self.assertTrue(disable_transaction_acquired.is_set())
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 1)
        row = self.store.query(
            "SELECT used_count FROM capability_grants WHERE grant_id = ?",
            (grant.grant_id,),
        )[0]
        self.assertEqual(row["used_count"], 1)

    def test_idempotent_consumption_is_atomic_under_concurrency(self) -> None:
        grant = self._grant(max_uses=1, cost_limit=0)
        barrier = threading.Barrier(2)
        results = []
        errors = []

        def consume() -> None:
            try:
                barrier.wait()
                results.append(
                    self._consume(
                        grant.grant_id,
                        idempotency_key="same-effect",
                        cost=0,
                    )
                )
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        threads = [threading.Thread(target=consume) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual({result.replayed for result in results}, {False, True})
        row = self.store.query(
            "SELECT used_count, cost_used FROM capability_grants WHERE grant_id = ?",
            (grant.grant_id,),
        )[0]
        self.assertEqual(row["used_count"], 1)
        self.assertEqual(row["cost_used"], 0)

    def test_usage_replay_without_effect_receipt_revalidates_revocation(self) -> None:
        grant = self._grant(max_uses=2)
        self._consume(grant.grant_id, effect_id="effect-1")
        self.policy.revoke_grant(grant.grant_id, actor=self.identities.owner)
        with self.assertRaises(AuthorizationError):
            self._consume(grant.grant_id, effect_id="effect-1")
        with self.assertRaises(AuthorizationError):
            self._consume(grant.grant_id, idempotency_key="new-use", cost=0)

    def test_policy_mutations_require_authenticated_independent_sessions(self) -> None:
        with self.assertRaisesRegex(AuthorizationError, "authenticated session"):
            self.policy.record_approval(
                project_id="project-1",
                goal_id="goal-1",
                run_id="run-1",
                task_id="task-1",
                requester="worker-forgery",  # type: ignore[arg-type]
                approver=self.identities.owner,
                capability=Capability.WRITE_LOCAL,
                action="write",
                resource="resource://one",
                request_digest=self.digest,
                policy_version="policy-v1",
                decision="approved",
                ttl_seconds=600,
            )
        with self.assertRaisesRegex(AuthorizationError, "authenticated session"):
            self.policy.record_approval(
                project_id="project-1",
                goal_id="goal-1",
                run_id="run-1",
                task_id="task-1",
                requester=self.identities.worker,
                approver="owner-forgery",  # type: ignore[arg-type]
                capability=Capability.WRITE_LOCAL,
                action="write",
                resource="resource://one",
                request_digest=self.digest,
                policy_version="policy-v1",
                decision="approved",
                ttl_seconds=600,
            )
        with self.assertRaisesRegex(AuthorizationError, "must be different"):
            self._approval(requester=self.identities.owner)

        approval = self._approval()
        issue_values: dict[str, Any] = {
            "approval_id": approval.approval_id,
            "capability": Capability.WRITE_LOCAL,
            "action": "write",
            "resource": "resource://one",
            "request_digest": self.digest,
            "policy_version": "policy-v1",
            "ttl_seconds": 300,
        }
        with self.assertRaisesRegex(AuthorizationError, "authenticated session"):
            self.policy.issue_grant(
                **issue_values,
                issuer="owner-forgery",  # type: ignore[arg-type]
                principal=self.identities.worker,
            )
        with self.assertRaisesRegex(AuthorizationError, "authenticated session"):
            self.policy.issue_grant(
                **issue_values,
                issuer=self.identities.owner,
                principal="worker-forgery",  # type: ignore[arg-type]
            )

        grant = self._grant()
        with self.assertRaisesRegex(AuthorizationError, "authenticated session"):
            self.policy.revoke_grant(
                grant.grant_id,
                actor="owner-forgery",  # type: ignore[arg-type]
            )

    def test_denied_expired_and_over_budget_grants_cannot_be_used(self) -> None:
        with self.assertRaises(AuthorizationError):
            self._approval(requester=self.identities.owner)

        denied = self._approval(decision="denied")
        with self.assertRaises(AuthorizationError):
            self.policy.issue_grant(
                approval_id=denied.approval_id,
                issuer=self.identities.owner,
                principal=self.identities.worker,
                capability=Capability.WRITE_LOCAL,
                action="write",
                resource="resource://one",
                request_digest=self.digest,
                policy_version="policy-v1",
                ttl_seconds=60,
            )

        provider_digest = content_hash({"operation": "provider-call"})
        over_budget = self._grant(
            capability=Capability.PROVIDER_COST,
            action="invoke",
            resource="provider://fake",
            digest=provider_digest,
            max_uses=2,
            cost_limit=50,
        )
        self._consume(
            over_budget.grant_id,
            capability=Capability.PROVIDER_COST,
            action="invoke",
            resource="provider://fake",
            request_digest=provider_digest,
            cost=40,
        )
        with self.assertRaises(AuthorizationError):
            self._consume(
                over_budget.grant_id,
                capability=Capability.PROVIDER_COST,
                action="invoke",
                resource="provider://fake",
                request_digest=provider_digest,
                idempotency_key="use-2",
                cost=20,
            )

        expired = self._grant()
        with self.store.transaction(immediate=True) as connection:
            connection.execute(
                """
                UPDATE capability_grants
                SET not_before = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-2 seconds'),
                    expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 second')
                WHERE grant_id = ?
                """,
                (expired.grant_id,),
            )
        with self.assertRaises(AuthorizationError):
            self._consume(expired.grant_id)

    def test_required_fence_must_still_be_current(self) -> None:
        leases = LeaseManager(self.store)
        worker_one = self.identities.worker
        worker_two = self.identities.worker_named("worker-two")
        lease = leases.acquire(
            resource_key="resource://one",
            project_id="project-1",
            task_id="task-1",
            holder=worker_one,
            ttl_seconds=300,
        )
        grant = self._grant(max_uses=2, required_fence=lease.fence)
        self._consume(grant.grant_id, fence=lease.fence, cost=0)
        leases.release(
            resource_key="resource://one",
            project_id="project-1",
            task_id="task-1",
            holder=worker_one,
            fence=lease.fence,
        )
        replacement = leases.acquire(
            resource_key="resource://one",
            project_id="project-1",
            task_id="task-1",
            holder=worker_two,
            ttl_seconds=300,
        )
        self.assertGreater(replacement.fence, lease.fence)
        with self.assertRaises(AuthorizationError):
            self._consume(
                grant.grant_id,
                idempotency_key="stale-fence-use",
                fence=lease.fence,
                cost=0,
            )

    def test_memory_promotion_capability_is_not_rule_promotion(self) -> None:
        capability = Capability.DURABLE_MEMORY_PROMOTION
        digest = content_hash({"memory_id": "memory-1", "decision": "promote"})
        requester = self.identities.session("promotion-requester", Role.OWNER)
        approval = self._approval(
            capability=capability,
            action="promote_memory",
            resource="memory://memory-1",
            digest=digest,
            requester=requester,
        )
        self.assertEqual(approval.capability, capability.value)
        with self.assertRaisesRegex(AuthorizationError, "governance decision"):
            self.policy.issue_grant(
                approval_id=approval.approval_id,
                issuer=self.identities.owner,
                principal=requester,
                capability=capability,
                action="promote_memory",
                resource="memory://memory-1",
                request_digest=digest,
                policy_version="policy-v1",
                ttl_seconds=300,
            )
        with self.assertRaisesRegex(AuthorizationError, "not allowed"):
            self._approval(
                capability=capability,
                action="promote_improvement:active",
                resource="memory://memory-1",
                digest=digest,
            )


if __name__ == "__main__":
    unittest.main()
