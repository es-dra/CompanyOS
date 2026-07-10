"""A complete zero-provider-cost vertical slice for runtime verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from .errors import AuthorizationError, SimulatedCrash, TransitionError
from .evaluation import EvalResultAttestation, EvaluationRegistry
from .evidence import EvidenceRegistry
from .fake_provider import FakeProvider
from .integration import IntegrationQueue
from .identity import IdentityManager, Role, VerifiedPrincipal
from .kernel import RuntimeKernel
from .leases import LeaseManager
from .observations import ObservationRegistry
from .policy import PolicyEngine
from .replay import ProjectionReplayer
from .scheduler import TaskScheduler
from .store import SQLiteStore
from .types import (
    Capability,
    EvaluatorVerdict,
    GoalSpec,
    IntegrationState,
    LoopEvent,
    RuntimeSurfaceSpec,
    TaskSpec,
    canonical_json,
    content_hash,
)
from .workflow import DurableWorkflow


FAULT_POINTS = {
    None,
    "before_effect",
    "after_effect_before_checkpoint",
    "after_checkpoint",
}


class _DemoEvalVerifier:
    """Verify in-process demo attestations with an ephemeral HMAC key."""

    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)
        self.authority_id = (
            "companyos.demo.eval-verifier.ephemeral-hmac."
            f"{content_hash(self._key.hex())}"
        )

    @staticmethod
    def _payload(attestation: EvalResultAttestation) -> dict[str, Any]:
        return {
            "attestation_id": attestation.attestation_id,
            "eval_id": attestation.eval_id,
            "project_id": attestation.project_id,
            "candidate_digest": attestation.candidate_digest,
            "dataset_name": attestation.dataset_name,
            "dataset_split": attestation.dataset_split,
            "dataset_digest": attestation.dataset_digest,
            "evaluator_principal_id": attestation.evaluator_principal_id,
            "evaluator_version": attestation.evaluator_version,
            "status": attestation.status,
            "metrics": dict(attestation.metrics),
            "safety_failures": list(attestation.safety_failures),
            "policy_version": attestation.policy_version,
        }

    def sign(self, attestation: EvalResultAttestation) -> str:
        return hmac.new(
            self._key,
            canonical_json(self._payload(attestation)).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, attestation: EvalResultAttestation) -> None:
        expected = self.sign(attestation)
        if not hmac.compare_digest(attestation.proof, expected):
            raise AuthorizationError("demo evaluation attestation is invalid")


def _demo_attestation(
    verifier: _DemoEvalVerifier,
    *,
    eval_id: str,
    project_id: str,
    candidate_digest: str,
    dataset_name: str,
    dataset_split: str,
    dataset_digest: str,
    evaluator: VerifiedPrincipal,
    status: str,
    metrics: Mapping[str, float | int],
    policy_version: str,
) -> EvalResultAttestation:
    unsigned = EvalResultAttestation(
        attestation_id=f"demo-attestation:{eval_id}",
        proof="",
        eval_id=eval_id,
        project_id=project_id,
        candidate_digest=candidate_digest,
        dataset_name=dataset_name,
        dataset_split=dataset_split,
        dataset_digest=dataset_digest,
        evaluator_principal_id=evaluator.principal_id,
        evaluator_version="1",
        status=status,
        metrics={key: float(value) for key, value in metrics.items()},
        safety_failures=(),
        policy_version=policy_version,
    )
    return replace(unsigned, proof=verifier.sign(unsigned))


def _demo_principals(
    store: SQLiteStore, demo_id: str
) -> tuple[VerifiedPrincipal, VerifiedPrincipal, VerifiedPrincipal]:
    identities = IdentityManager(store)
    owner_name = "companyos-zero-cost-demo-control"
    owner_credential = "companyos-zero-cost-demo-control-only-v1"
    principal_count = store.query("SELECT COUNT(*) AS count FROM principals")[0][
        "count"
    ]
    if principal_count == 0:
        owner = identities.bootstrap_owner(
            display_name=owner_name, credential=owner_credential
        )
    else:
        owner = identities.authenticate(
            display_name=owner_name, credential=owner_credential
        )
    identities.set_roles(
        owner,
        display_name=owner_name,
        roles={Role.OWNER, Role.SYSTEM, Role.RELEASE, Role.OBSERVER},
    )

    def create_session(name: str, role: Role) -> VerifiedPrincipal:
        credential = f"companyos-zero-cost-demo-{name}-credential-v1"
        identities.create_principal(
            owner,
            display_name=name,
            credential=credential,
            roles={role},
        )
        return identities.authenticate(display_name=name, credential=credential)

    worker = create_session(f"demo-worker-{demo_id}", Role.WORKER)
    evaluator = create_session(f"demo-evaluator-{demo_id}", Role.EVALUATOR)
    return owner, worker, evaluator


def run_zero_cost_demo(
    state_dir: str | Path,
    *,
    fault_at: str | None = "after_effect_before_checkpoint",
) -> dict[str, Any]:
    """Run a bounded end-to-end workflow using only local SQLite files.

    The resulting evidence level is ``runtime_verification``. It deliberately
    does not claim provider smoke, human acceptance, business validation, or
    active-rule promotion.
    """

    if fault_at not in FAULT_POINTS:
        raise ValueError(f"unsupported fault point: {fault_at}")
    root = Path(state_dir).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    store = SQLiteStore(root / "runtime.db")
    provider = FakeProvider(root / "fake-provider.db")
    kernel = RuntimeKernel(store)
    workflow = DurableWorkflow(store, provider)
    workflow.initialize()
    demo_id = uuid.uuid4().hex[:12]
    project_id = "companyos-runtime-demo"
    goal_id = f"goal-{demo_id}"
    run_id = f"run-{demo_id}"
    task_id = f"task-{demo_id}"
    resource = f"fake://ledger/{demo_id}"
    request = {
        "operation": "write",
        "key": demo_id,
        "value": "synthetic-runtime-proof",
    }
    request_digest = content_hash(request)
    owner, worker, evaluator = _demo_principals(store, demo_id)
    runtime_surface = RuntimeSurfaceSpec(
        surface_key="fake-provider-ledger",
        target_identity=f"sqlite:{provider.path}",
        allowed_probes=("sqlite-ledger-count",),
        max_ttl_seconds=300,
        trigger_event_required=True,
    )

    goal = GoalSpec.from_dict(
        {
            "goal_id": goal_id,
            "target_outcome": "prove crash-safe bounded execution with zero provider cost",
            "success_evidence_states": ["runtime_verification"],
            "write_scope": ["fake://ledger"],
            "forbidden_scope": [
                "provider://paid",
                "server://production",
                "repo://unrelated-project",
            ],
            "allowed_capabilities": ["read_local", "write_local"],
            "required_runtime_surfaces": [runtime_surface.to_dict()],
            "evaluator_required": True,
            "max_iterations_without_evidence": 3,
            "non_goals": [
                "provider_smoke",
                "human_acceptance",
                "business_validation",
                "active_rule_promotion",
            ],
        }
    )
    task = TaskSpec.from_dict(
        {
            "task_id": task_id,
            "goal_id": goal_id,
            "objective": "write one idempotent synthetic effect and recover from a crash",
            "expected_delta": "runtime",
            "primary_surface": resource,
            "evidence_target": "runtime_verification",
            "capabilities": ["write_local"],
            "write_scope": [resource],
            "forbidden_scope": [
                "provider://paid",
                "server://production",
                "repo://unrelated-project",
            ],
            "required_runtime_surfaces": [runtime_surface.to_dict()],
            "evaluator_required": True,
            "integration_required": True,
            "workflow_steps": [
                {
                    "step_id": "synthetic-write",
                    "adapter": "fake-provider",
                    "action": "synthetic_write",
                    "resource": resource,
                    "request_digest": request_digest,
                }
            ],
            "max_attempts": 3,
        }
    )

    kernel.create_goal(
        project_id=project_id,
        spec=goal,
        actor=owner,
        idempotency_key=f"{demo_id}:goal",
    )
    kernel.create_run(
        project_id=project_id,
        goal_id=goal_id,
        run_id=run_id,
        actor=owner,
        idempotency_key=f"{demo_id}:run",
    )
    kernel.add_task(
        project_id=project_id,
        run_id=run_id,
        spec=task,
        actor=owner,
        idempotency_key=f"{demo_id}:task",
    )
    kernel.advance_loop(
        run_id=run_id,
        event=LoopEvent.GOAL_COMPILED,
        actor=owner,
        idempotency_key=f"{demo_id}:compiled",
    )
    kernel.advance_loop(
        run_id=run_id,
        event=LoopEvent.RUN_READY,
        actor=owner,
        idempotency_key=f"{demo_id}:ready",
    )

    scheduler = TaskScheduler(store)
    task_claim = scheduler.claim_next(
        project_id=project_id, worker=worker, ttl_seconds=600
    )
    if task_claim is None:
        raise RuntimeError("demo scheduler could not claim its task")
    lease = LeaseManager(store).acquire(
        resource_key=resource,
        project_id=project_id,
        task_id=task_id,
        holder=worker,
        ttl_seconds=600,
    )
    kernel.advance_loop(
        run_id=run_id,
        event=LoopEvent.TASK_STARTED,
        actor=worker,
        idempotency_key=f"{demo_id}:started",
        payload={
            "task_id": task_id,
            "resource_key": resource,
            "holder": worker.principal_id,
            "fence": lease.fence,
        },
    )
    scheduler.start(task_claim, worker=worker)

    policy = PolicyEngine(store)
    approval = policy.record_approval(
        project_id=project_id,
        goal_id=goal_id,
        run_id=run_id,
        task_id=task_id,
        requester=worker,
        approver=owner,
        capability=Capability.WRITE_LOCAL,
        action="synthetic_write",
        resource=resource,
        request_digest=request_digest,
        policy_version=kernel.policy_version,
        decision="approved",
        ttl_seconds=600,
    )
    grant = policy.issue_grant(
        approval_id=approval.approval_id,
        issuer=owner,
        principal=worker,
        capability=Capability.WRITE_LOCAL,
        action="synthetic_write",
        resource=resource,
        request_digest=request_digest,
        policy_version=kernel.policy_version,
        ttl_seconds=300,
        max_uses=1,
        cost_limit=0,
        required_fence=lease.fence,
    )
    before_count = provider.effect_count()
    effect = workflow.enqueue(
        task_id=task_id,
        step_id="synthetic-write",
        adapter="fake-provider",
        idempotency_key=f"{demo_id}:effect",
        request=request,
        grant_id=grant.grant_id,
        principal=worker,
        capability=Capability.WRITE_LOCAL,
        action="synthetic_write",
        resource=resource,
        fence=lease.fence,
    )
    crash_observed = False
    try:
        workflow.dispatch(effect.effect_id, fault_at=fault_at)
    except SimulatedCrash:
        crash_observed = True
    workflow.recover_pending()
    receipt_row = store.query(
        "SELECT * FROM effect_receipts WHERE effect_id = ?", (effect.effect_id,)
    )[0]
    effect_result = json.loads(receipt_row["result_json"])
    after_count = provider.effect_count()

    scheduler.complete(task_claim, worker=worker)
    evidence = EvidenceRegistry(store)
    artifact = evidence.register_artifact(
        task_id=task_id,
        kind="synthetic_effect_receipt",
        uri=f"fake-receipt://{receipt_row['provider_receipt']}",
        content_digest=content_hash(effect_result),
        confidentiality="internal",
        producer_session=worker,
    )
    claim = evidence.record_claim(
        task_id=task_id,
        claim="the local runtime reconciled one fenced, idempotent synthetic effect after fault injection",
        evidence_state="runtime_verification",
        artifact_refs=[artifact.artifact_id],
        verifier_session=evaluator,
        verifier_version="1",
        environment="synthetic",
        evaluator_verdict=EvaluatorVerdict.PASS,
        non_claims=(
            "provider_smoke",
            "human_acceptance",
            "business_validation",
            "active_rule_promotion",
            "multi-host exactly-once",
        ),
    )
    kernel.advance_loop(
        run_id=run_id,
        event=LoopEvent.EVIDENCE_SUBMITTED,
        actor=worker,
        idempotency_key=f"{demo_id}:evidence-submitted",
        payload={"task_id": task_id, "evidence_id": claim.evidence_id},
    )
    kernel.accept_task_evidence(
        task_id=task_id,
        actor=evaluator,
        idempotency_key=f"{demo_id}:task-evaluator",
        evidence_id=claim.evidence_id,
    )
    kernel.advance_loop(
        run_id=run_id,
        event=LoopEvent.EVALUATOR_VERDICT_RECEIVED,
        actor=evaluator,
        idempotency_key=f"{demo_id}:evaluated",
        payload={"task_id": task_id, "evidence_id": claim.evidence_id},
    )
    queue = IntegrationQueue(store)
    item = queue.create(
        task_id=task_id,
        source_ref=f"effect://{effect.effect_id}",
        target_ref=f"local://runtime/{demo_id}",
        owner=owner,
        evidence_refs=[claim.evidence_id],
    )
    queue.advance(
        item.integration_id,
        target=IntegrationState.DELIVERED,
        actor=owner,
        reason="local synthetic receipt reconciled; no remote/server/provider surface exists",
        evidence_refs=[claim.evidence_id],
    )
    integration_event = store.query(
        "SELECT event_id FROM events WHERE aggregate_type = 'integration' "
        "AND aggregate_id = ? ORDER BY seq DESC LIMIT 1",
        (item.integration_id,),
    )[0]["event_id"]
    ObservationRegistry(store).record(
        project_id=project_id,
        run_id=run_id,
        surface_key=runtime_surface.surface_key,
        target_identity=runtime_surface.target_identity,
        observer=owner,
        probe_name=runtime_surface.allowed_probes[0],
        probe_version="1",
        status="healthy",
        value={
            "effect_id": effect.effect_id,
            "effect_count_delta": after_count - before_count,
        },
        ttl_seconds=60,
        trigger_event_id=integration_event,
    )
    kernel.confirm_task_delivery(
        task_id=task_id,
        actor=owner,
        idempotency_key=f"{demo_id}:task-delivered",
    )
    kernel.advance_loop(
        run_id=run_id,
        event=LoopEvent.DELIVERY_CONFIRMED,
        actor=owner,
        idempotency_key=f"{demo_id}:delivery",
    )

    eval_verifier = _DemoEvalVerifier()
    evaluations = EvaluationRegistry(store, result_verifier=eval_verifier)
    candidate_digest = content_hash(
        {
            "surface": "workflow_parameter",
            "proposal": "retain fault-point matrix in regression suite",
        }
    )
    proposal = evaluations.propose(
        project_id=project_id,
        source_run_id=run_id,
        hypothesis="retaining deterministic crash points reduces recovery regressions",
        candidate_digest=candidate_digest,
        editable_surface="workflow_parameter",
        expected_benefit="earlier recovery regression detection",
        risk="synthetic coverage may be mistaken for provider coverage",
        rollback_route="retire the candidate without altering active policy",
        proposer=worker,
    )
    held_in_id = f"eval-{demo_id}-held-in"
    held_in_dataset = content_hash("held-in-crash-fixtures-v1")
    held_in_metrics = {"recovery_rate": 1.0, "duplicate_effects": 0}
    held_in = evaluations.record_eval(
        project_id=project_id,
        candidate_digest=candidate_digest,
        dataset_name="synthetic-crash-matrix",
        dataset_split="held_in",
        dataset_digest=held_in_dataset,
        evaluator=evaluator,
        evaluator_version="1",
        status="pass",
        metrics=held_in_metrics,
        eval_id=held_in_id,
        attestation=_demo_attestation(
            eval_verifier,
            eval_id=held_in_id,
            project_id=project_id,
            candidate_digest=candidate_digest,
            dataset_name="synthetic-crash-matrix",
            dataset_split="held_in",
            dataset_digest=held_in_dataset,
            evaluator=evaluator,
            status="pass",
            metrics=held_in_metrics,
            policy_version=kernel.policy_version,
        ),
    )
    evaluations.attach_eval(proposal.proposal_id, held_in.eval_id, actor=owner)
    held_out_id = f"eval-{demo_id}-held-out"
    held_out_dataset = content_hash("held-out-crash-fixtures-v1")
    held_out_metrics = {"recovery_rate": 1.0, "duplicate_effects": 0}
    held_out = evaluations.record_eval(
        project_id=project_id,
        candidate_digest=candidate_digest,
        dataset_name="synthetic-crash-matrix-heldout",
        dataset_split="held_out",
        dataset_digest=held_out_dataset,
        evaluator=evaluator,
        evaluator_version="1",
        status="pass",
        metrics=held_out_metrics,
        eval_id=held_out_id,
        attestation=_demo_attestation(
            eval_verifier,
            eval_id=held_out_id,
            project_id=project_id,
            candidate_digest=candidate_digest,
            dataset_name="synthetic-crash-matrix-heldout",
            dataset_split="held_out",
            dataset_digest=held_out_dataset,
            evaluator=evaluator,
            status="pass",
            metrics=held_out_metrics,
            policy_version=kernel.policy_version,
        ),
    )
    proposal = evaluations.attach_eval(
        proposal.proposal_id, held_out.eval_id, actor=owner
    )
    try:
        evaluations.build_limited_promotion_request(
            proposal.proposal_id,
            source_task_id=task_id,
            verification_evidence_id=claim.evidence_id,
            scope=f"project://{project_id}/workflow_parameter/demo-only",
            actual_outcome_kind="failure_prevented",
            actual_outcome=claim.claim,
            non_goals=(
                "real project trial",
                "active rule promotion",
                "external sealed custody",
            ),
            review_condition="replace synthetic evidence with a real delivered task",
            rollback_or_retirement_path=proposal.rollback_route,
            non_claim_boundary=(
                "synthetic zero-cost demo evidence cannot support limited promotion"
            ),
        )
    except TransitionError:
        limited_gate_status = "blocked_synthetic_evidence"
    else:  # pragma: no cover - a regression must fail the demo loudly
        raise RuntimeError(
            "synthetic demo evidence unexpectedly satisfied the real-task limited gate"
        )
    kernel.advance_loop(
        run_id=run_id,
        event=LoopEvent.IMPROVEMENT_REQUESTED,
        actor=owner,
        idempotency_key=f"{demo_id}:improvement",
    )
    kernel.advance_loop(
        run_id=run_id,
        event=LoopEvent.DELIVERY_CONFIRMED,
        actor=owner,
        idempotency_key=f"{demo_id}:improvement-routed",
    )

    replayed = ProjectionReplayer(store).verify()
    cost = store.query(
        "SELECT COALESCE(SUM(cost_used), 0) AS total FROM capability_grants"
    )[0]["total"]
    return {
        "demo_id": demo_id,
        "state_dir": str(root),
        "fault_at": fault_at,
        "simulated_crash_observed": crash_observed,
        "run_state": kernel.get_run(run_id)["loop_state"],
        "task_state": kernel.get_task(task_id)["state"],
        "effect_status": receipt_row["status"],
        "external_effect_delta": after_count - before_count,
        "event_chain_length": store.verify_event_chain(),
        "replayed_core_objects": {
            "goals": len(replayed.goals),
            "runs": len(replayed.runs),
            "tasks": len(replayed.tasks),
        },
        "evidence_state": "runtime_verification",
        "evidence_id": claim.evidence_id,
        "improvement_state": proposal.state.value,
        "limited_gate_status": limited_gate_status,
        "provider_cost": float(cost),
        "non_claims": [
            "provider_smoke",
            "human_acceptance",
            "business_validation",
            "legal_acceptance",
            "public_release",
            "active_rule_promotion",
            "multi-host exactly-once",
        ],
    }
