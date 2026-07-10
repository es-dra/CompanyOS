"""Exact, local-only evaluation attestations for deterministic tests."""

from __future__ import annotations

import hmac
from collections.abc import Iterable, Mapping

from companyos_runtime.errors import AuthorizationError
from companyos_runtime.evaluation import EvalResultAttestation
from companyos_runtime.identity import VerifiedPrincipal


TEST_EVAL_PROOF = "companyos-local-test-eval-proof-v1"


class ExactTestEvalVerifier:
    """Accept only attestations minted by ``make_eval_attestation``."""

    def verify(self, attestation: EvalResultAttestation) -> None:
        expected_id = f"test-attestation:{attestation.eval_id}"
        if not hmac.compare_digest(attestation.proof, TEST_EVAL_PROOF):
            raise AuthorizationError("test evaluation proof is invalid")
        if attestation.attestation_id != expected_id:
            raise AuthorizationError("test evaluation attestation id is invalid")


def make_eval_attestation(
    *,
    eval_id: str,
    project_id: str,
    candidate_digest: str,
    dataset_name: str,
    dataset_split: str,
    dataset_digest: str,
    evaluator: VerifiedPrincipal,
    evaluator_version: str,
    status: str,
    metrics: Mapping[str, float | int],
    safety_failures: Iterable[str] = (),
    policy_version: str = "companyos-policy-v1",
) -> EvalResultAttestation:
    return EvalResultAttestation(
        attestation_id=f"test-attestation:{eval_id}",
        proof=TEST_EVAL_PROOF,
        eval_id=eval_id,
        project_id=project_id,
        candidate_digest=candidate_digest,
        dataset_name=dataset_name,
        dataset_split=dataset_split,
        dataset_digest=dataset_digest,
        evaluator_principal_id=evaluator.principal_id,
        evaluator_version=evaluator_version,
        status=status,
        metrics={key: float(value) for key, value in metrics.items()},
        safety_failures=tuple(safety_failures),
        policy_version=policy_version,
    )
