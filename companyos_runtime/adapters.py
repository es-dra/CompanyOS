"""Minimal side-effect adapter protocol and reusable conformance harness."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .errors import IntegrityError, RuntimeKernelError
from .types import content_hash


@dataclass(frozen=True)
class AdapterReceipt:
    adapter_id: str
    project_id: str
    idempotency_key: str
    effect_id: str
    request_digest: str
    provider_receipt: str | None
    status: str
    closed: bool
    result: Mapping[str, Any]
    replayed: bool


class WorkflowAdapter(Protocol):
    """Project adapter boundary required by ``DurableWorkflow`` recovery."""

    @property
    def adapter_id(self) -> str: ...

    def initialize(self) -> None: ...

    def execute(
        self,
        *,
        project_id: str,
        idempotency_key: str,
        effect_id: str,
        request_digest: str,
        request: Mapping[str, Any],
    ) -> AdapterReceipt: ...

    def lookup(
        self,
        *,
        project_id: str,
        idempotency_key: str,
        effect_id: str,
        request_digest: str,
    ) -> AdapterReceipt | None: ...


@dataclass(frozen=True)
class AdapterConformanceReport:
    adapter_name: str
    status: str
    checks: Mapping[str, str]
    evidence_state: str = "runtime_verification"
    non_claims: tuple[str, ...] = (
        "provider_production_health",
        "provider_exactly_once",
        "multi_host_delivery",
        "business_validation",
    )

    def to_wire(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "status": self.status,
            "checks": dict(self.checks),
            "evidence_state": self.evidence_state,
            "non_claims": list(self.non_claims),
        }


def _expect_rejected(action: Any, check: str) -> None:
    try:
        action()
    except RuntimeKernelError:
        return
    except Exception as exc:
        raise IntegrityError(
            f"adapter conformance crashed instead of rejecting: {check}"
        ) from exc
    raise IntegrityError(f"adapter conformance failed open: {check}")


def run_adapter_conformance(
    adapter: WorkflowAdapter,
    *,
    adapter_name: str,
    project_id: str | None = None,
) -> AdapterConformanceReport:
    """Exercise an explicitly isolated adapter test surface.

    This creates one real adapter effect. Callers must supply a sandbox/test
    adapter and independently gate any network, provider cost, or remote write.
    """

    if not isinstance(adapter_name, str) or not adapter_name.strip():
        raise IntegrityError("adapter_name must be non-empty")
    adapter_name = adapter_name.strip()
    if adapter.adapter_id != adapter_name:
        raise IntegrityError("adapter_name must exactly match adapter.adapter_id")
    run_id = uuid.uuid4().hex
    project = project_id or f"companyos-conformance-{run_id}"
    idempotency_key = f"conformance-{run_id}"
    effect_id = f"effect-{run_id}"
    request = {"operation": "conformance_probe", "nonce": run_id}
    request_digest = content_hash(request)

    missing = adapter.lookup(
        project_id=project,
        idempotency_key=idempotency_key,
        effect_id=effect_id,
        request_digest=request_digest,
    )
    if missing is not None:
        raise IntegrityError("adapter lookup returned an effect before execution")
    first = adapter.execute(
        project_id=project,
        idempotency_key=idempotency_key,
        effect_id=effect_id,
        request_digest=request_digest,
        request=request,
    )
    expected_identity = (
        adapter_name,
        project,
        idempotency_key,
        effect_id,
        request_digest,
    )
    if (
        first.replayed
        or first.status != "succeeded"
        or not first.closed
        or (
            first.adapter_id,
            first.project_id,
            first.idempotency_key,
            first.effect_id,
            first.request_digest,
        )
        != expected_identity
    ):
        raise IntegrityError("adapter first execution receipt is invalid")
    looked_up = adapter.lookup(
        project_id=project,
        idempotency_key=idempotency_key,
        effect_id=effect_id,
        request_digest=request_digest,
    )
    if looked_up is None or not looked_up.replayed:
        raise IntegrityError("adapter cannot reconcile the committed effect")
    replayed = adapter.execute(
        project_id=project,
        idempotency_key=idempotency_key,
        effect_id=effect_id,
        request_digest=request_digest,
        request=request,
    )
    expected = (
        expected_identity,
        first.provider_receipt,
        first.status,
        first.closed,
        dict(first.result),
    )
    for receipt in (looked_up, replayed):
        if (
            not receipt.replayed
            or (
                (
                    receipt.adapter_id,
                    receipt.project_id,
                    receipt.idempotency_key,
                    receipt.effect_id,
                    receipt.request_digest,
                ),
                receipt.provider_receipt,
                receipt.status,
                receipt.closed,
                dict(receipt.result),
            )
            != expected
        ):
            raise IntegrityError("adapter replay receipt changed")

    _expect_rejected(
        lambda: adapter.execute(
            project_id=project,
            idempotency_key=idempotency_key,
            effect_id=effect_id,
            request_digest=request_digest,
            request={**request, "changed": True},
        ),
        "request digest mismatch",
    )
    _expect_rejected(
        lambda: adapter.lookup(
            project_id=project,
            idempotency_key=idempotency_key,
            effect_id=f"{effect_id}-other",
            request_digest=request_digest,
        ),
        "idempotency key reused with another effect",
    )
    _expect_rejected(
        lambda: adapter.lookup(
            project_id=project,
            idempotency_key=idempotency_key,
            effect_id=effect_id,
            request_digest="0" * 64,
        ),
        "idempotency key reused with another digest",
    )
    cross_project = adapter.lookup(
        project_id=f"{project}-isolated",
        idempotency_key=idempotency_key,
        effect_id=effect_id,
        request_digest=request_digest,
    )
    if cross_project is not None:
        raise IntegrityError("adapter leaked an idempotency key across projects")
    return AdapterConformanceReport(
        adapter_name=adapter_name,
        status="passed",
        checks={
            "lookup_before_execute": "absent",
            "first_execute": "durable_receipt",
            "lookup_reconciliation": "passed",
            "idempotent_replay": "passed",
            "request_digest_mismatch": "rejected",
            "effect_identity_mismatch": "rejected",
            "project_idempotency_isolation": "passed",
            "receipt_identity": "stable",
        },
    )
