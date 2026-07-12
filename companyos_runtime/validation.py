"""Repository and installed-runtime validation without provider/network access."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import MISSING, fields
from pathlib import Path
from typing import Any

from .errors import ContractError
from .evaluation import (
    ActiveRulePromotionRecord,
    LimitedRulePromotionRecord,
    LimitedRulePromotionRequest,
)
from .leases import LeaseRecord
from .types import (
    Capability,
    EvidenceState,
    GoalSpec,
    IntegrationState,
    RuntimeSurfaceSpec,
    TaskSpec,
    content_hash,
)
from .workflow import EffectReceipt, OutboxEffect


DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
CANONICAL_CONTRACT = "runtime/contracts/v1/runtime-contracts.schema.json"
AUTHORITY_CONTRACT = "runtime/contracts/v1/authority-spine.schema.json"
AUTHORING_CONTRACT = "runtime/contracts/v1/authoring-contracts.schema.json"
COMPATIBILITY_MANIFEST = "runtime/contracts/v1/compatibility-manifest.json"

REQUIRED_FILES = (
    ".gitattributes",
    "VERSION",
    "pyproject.toml",
    "companyos_runtime/__init__.py",
    "AGENTS.md",
    "README.md",
    "core/authority-order.md",
    "core/evidence-states.md",
    "gfr/startup-contract.md",
    CANONICAL_CONTRACT,
    AUTHORITY_CONTRACT,
    AUTHORING_CONTRACT,
    COMPATIBILITY_MANIFEST,
    "runtime/run-log.schema.json",
    "runtime/feedback-export.schema.json",
    "runtime/project-adoption.schema.json",
    "runtime/projection-decision.schema.json",
    "templates/AOS_STARTUP_PACKET.md",
    "templates/GOAL_CONTRACT.md",
    "templates/TASK_PACKET.md",
    "templates/EVIDENCE_PACKET.md",
    "templates/RUNTIME_SURFACE_VECTOR.md",
    "companyos_runtime/compiler.py",
    "docs/runtime-architecture.md",
    "docs/operations-runbook.md",
    "docs/adapter-conformance.md",
    "docs/evaluation-plan.md",
    "docs/migration-v0.2.md",
    "docs/source-sync.md",
    "docs/contributor-onboarding.md",
    "examples/feedback-export.example.json",
    "examples/project-adoption.example.json",
    "examples/projection-decision.example.json",
    "examples/authoring/goal-contract.full.json",
    "examples/authoring/task-packet.full.json",
)

EXAMPLE_SCHEMA_PAIRS = (
    (
        "examples/feedback-export.example.json",
        "runtime/feedback-export.schema.json",
    ),
    (
        "examples/project-adoption.example.json",
        "runtime/project-adoption.schema.json",
    ),
    (
        "examples/projection-decision.example.json",
        "runtime/projection-decision.schema.json",
    ),
    (
        "examples/authoring/goal-contract.full.json",
        AUTHORING_CONTRACT,
    ),
    (
        "examples/authoring/task-packet.full.json",
        AUTHORING_CONTRACT,
    ),
)

STRUCTURE_VALIDATION_NON_CLAIMS = (
    "runtime_verification",
    "provider_smoke",
    "human_acceptance",
    "business_validation",
    "legal_validation",
    "durable_memory_promotion",
    "active_rule_promotion",
    "real_adapter_conformance",
    "public_release",
    "multi_host_durability",
    "generic_exactly_once_delivery",
)


def _load_jsonschema() -> tuple[Any, Any, type[Exception], type[Exception]]:
    try:
        from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
        from jsonschema.exceptions import (  # type: ignore[import-untyped]
            SchemaError,
            ValidationError,
        )
    except (
        ImportError
    ) as exc:  # pragma: no cover - exercised in dependency-isolated use
        raise ContractError(
            "Draft 2020-12 contract validation requires jsonschema>=4.18; "
            "install the repository validation dependency and retry"
        ) from exc
    return Draft202012Validator, FormatChecker, SchemaError, ValidationError


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid JSON file: {path}") from exc


def _validate_instance(
    validator_type: Any,
    format_checker_type: Any,
    validation_error_type: type[Exception],
    schema: dict[str, Any],
    instance: Any,
    label: str,
) -> None:
    try:
        validator_type(schema, format_checker=format_checker_type()).validate(instance)
    except validation_error_type as exc:
        raise ContractError(
            f"JSON Schema instance validation failed for {label}: {exc}"
        ) from exc


def _dataclass_required_fields(contract_type: type[Any]) -> set[str]:
    return {
        item.name
        for item in fields(contract_type)
        if item.default is MISSING and item.default_factory is MISSING
    }


def _assert_exact_set(label: str, actual: set[str], expected: set[str]) -> None:
    if actual != expected:
        raise ContractError(
            f"{label} parity mismatch: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def _validate_contract_parity(
    contract: dict[str, Any], run_log_schema: dict[str, Any]
) -> None:
    definitions = contract.get("$defs")
    if not isinstance(definitions, dict):
        raise ContractError("canonical contract bundle must contain an object $defs")

    required_defs = {
        "GoalSpec",
        "TaskSpec",
        "EventEnvelope",
        "EvidenceClaim",
        "RuntimeObservation",
        "CapabilityGrant",
        "EvalRun",
        "IntegrationItem",
        "ContextItem",
        "MemoryItem",
        "Approval",
        "Lease",
        "TaskAttempt",
        "OutboxEffect",
        "EffectReceipt",
        "NegativeResult",
        "ImprovementProposal",
        "LimitedRulePromotionRequest",
        "LimitedRulePromotionRecord",
        "SealedCustodyRecord",
        "ActiveRulePromotionRecord",
    }
    if "RuntimeSurfaceSpec" not in definitions:
        raise ContractError(
            "contract bundle missing helper definition: RuntimeSurfaceSpec"
        )
    present_defs = set(definitions)
    if not required_defs <= present_defs:
        raise ContractError(
            f"contract bundle missing definitions: {sorted(required_defs - present_defs)}"
        )

    exported_defs = {
        item.get("$ref", "").removeprefix("#/$defs/")
        for item in contract.get("oneOf", [])
        if isinstance(item, dict) and item.get("$ref", "").startswith("#/$defs/")
    }
    _assert_exact_set(
        "top-level runtime definition export", exported_defs, required_defs
    )

    _assert_exact_set(
        "Capability enum",
        set(definitions["Capability"]["enum"]),
        {item.value for item in Capability},
    )
    _assert_exact_set(
        "EvidenceState enum",
        set(definitions["EvidenceState"]["enum"]),
        {item.value for item in EvidenceState},
    )
    _assert_exact_set(
        "IntegrationItem state enum",
        set(definitions["IntegrationItem"]["properties"]["state"]["enum"]),
        {item.value for item in IntegrationState},
    )
    _assert_exact_set(
        "run-log integration_queue_state enum",
        set(run_log_schema["properties"]["integration_queue_state"]["enum"]),
        {"none", *(item.value for item in IntegrationState)},
    )
    _assert_exact_set(
        "run-log evidence_state enum",
        set(run_log_schema["properties"]["evidence_state"]["enum"]),
        {"not_verified", *(item.value for item in EvidenceState)},
    )

    for name, contract_type in (("GoalSpec", GoalSpec), ("TaskSpec", TaskSpec)):
        definition = definitions[name]
        _assert_exact_set(
            f"{name} property",
            set(definition["properties"]),
            {item.name for item in fields(contract_type)},
        )
        _assert_exact_set(
            f"{name} required-field",
            set(definition["required"]),
            _dataclass_required_fields(contract_type),
        )
    surface_definition = definitions["RuntimeSurfaceSpec"]
    _assert_exact_set(
        "RuntimeSurfaceSpec property",
        set(surface_definition["properties"]),
        {item.name for item in fields(RuntimeSurfaceSpec)},
    )
    _assert_exact_set(
        "RuntimeSurfaceSpec required-field",
        set(surface_definition["required"]),
        _dataclass_required_fields(RuntimeSurfaceSpec),
    )
    promotion_definition = definitions["ActiveRulePromotionRecord"]
    _assert_exact_set(
        "ActiveRulePromotionRecord property",
        set(promotion_definition["properties"]),
        {item.name for item in fields(ActiveRulePromotionRecord)},
    )
    _assert_exact_set(
        "ActiveRulePromotionRecord required-field",
        set(promotion_definition["required"]),
        _dataclass_required_fields(ActiveRulePromotionRecord),
    )
    for schema_name, promotion_contract_type in (
        ("LimitedRulePromotionRequest", LimitedRulePromotionRequest),
        ("LimitedRulePromotionRecord", LimitedRulePromotionRecord),
    ):
        definition = definitions[schema_name]
        _assert_exact_set(
            f"{schema_name} property",
            set(definition["properties"]),
            {item.name for item in fields(promotion_contract_type)},
        )
        _assert_exact_set(
            f"{schema_name} required-field",
            set(definition["required"]),
            _dataclass_required_fields(promotion_contract_type),
        )
    for schema_name, wire_contract_type in (
        ("Lease", LeaseRecord),
        ("OutboxEffect", OutboxEffect),
        ("EffectReceipt", EffectReceipt),
    ):
        definition = definitions[schema_name]
        _assert_exact_set(
            f"{schema_name} wire property",
            set(definition["properties"]),
            {item.name for item in fields(wire_contract_type)},
        )
        _assert_exact_set(
            f"{schema_name} wire required-field",
            set(definition["required"]),
            _dataclass_required_fields(wire_contract_type),
        )


def _validate_compatibility_manifest(repo: Path) -> None:
    manifest_path = repo / COMPATIBILITY_MANIFEST
    manifest = _read_json(manifest_path)
    if set(manifest) != {
        "schema_version",
        "authoring_contract_version",
        "wire_schema_version",
        "package_version",
        "artifacts",
    }:
        raise ContractError("authoring compatibility manifest fields drifted")
    if manifest["schema_version"] != "companyos.authoring-compatibility.v1":
        raise ContractError("unsupported authoring compatibility manifest version")
    package_version = (repo / "VERSION").read_text(encoding="utf-8").strip()
    pyproject = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
    pyproject_version = pyproject.get("project", {}).get("version")
    init_text = (repo / "companyos_runtime/__init__.py").read_text(encoding="utf-8")
    version_matches = re.findall(
        r'(?m)^__version__\s*=\s*["\'](?P<version>[^"\']+)["\']\s*$',
        init_text,
    )
    if version_matches != [package_version] or pyproject_version != package_version:
        raise ContractError(
            "package version drifted across VERSION, pyproject.toml, and __version__"
        )
    if manifest["package_version"] != package_version:
        raise ContractError("compatibility manifest package version is stale")
    required_artifacts = {
        "compiler",
        "wire_schema",
        "authority_schema",
        "authoring_schema",
        "goal_template",
        "task_template",
        "goal_fixture",
        "task_fixture",
    }
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != required_artifacts:
        raise ContractError("compatibility manifest artifact inventory drifted")
    for name, record in artifacts.items():
        if not isinstance(record, dict) or set(record) != {
            "path",
            "sha256",
            "digest_mode",
        }:
            raise ContractError(f"compatibility manifest record is invalid: {name}")
        if record["digest_mode"] != "canonical_text_sha256":
            raise ContractError(
                f"compatibility manifest digest mode is unsupported: {name}"
            )
        path = (repo / record["path"]).resolve()
        try:
            path.relative_to(repo)
        except ValueError as exc:
            raise ContractError(
                f"compatibility manifest path escapes repository: {name}"
            ) from exc
        if not path.is_file():
            raise ContractError(f"compatibility artifact is missing: {name}")
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError(
                f"compatibility text artifact is not UTF-8: {name}"
            ) from exc
        canonical = text.replace("\r\n", "\n").replace("\r", "\n")
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if digest != record["sha256"]:
            raise ContractError(
                f"compatibility artifact digest drifted: {name}: "
                f"expected={record['sha256']} actual={digest}"
            )


def validate_repository(root: str | Path) -> dict[str, Any]:
    repo = Path(root).expanduser().resolve()
    missing = [name for name in REQUIRED_FILES if not (repo / name).is_file()]
    if missing:
        raise ContractError(f"repository is missing required files: {missing}")

    validator_type, format_checker_type, schema_error_type, validation_error_type = (
        _load_jsonschema()
    )
    json_paths = sorted(repo.glob("runtime/**/*.json")) + sorted(
        repo.glob("examples/**/*.json")
    )
    documents = {path.resolve(): _read_json(path) for path in json_paths}

    schema_count = 0
    for path, document in documents.items():
        if not path.name.endswith(".schema.json"):
            continue
        if not isinstance(document, dict) or document.get("$schema") != DRAFT_2020_12:
            raise ContractError(f"schema does not declare Draft 2020-12: {path}")
        try:
            validator_type.check_schema(document)
        except schema_error_type as exc:
            raise ContractError(f"invalid Draft 2020-12 schema: {path}: {exc}") from exc
        schema_count += 1

    contract_path = (repo / CANONICAL_CONTRACT).resolve()
    run_log_path = (repo / "runtime/run-log.schema.json").resolve()
    contract = documents[contract_path]
    run_log_schema = documents[run_log_path]
    if not isinstance(contract, dict) or not isinstance(run_log_schema, dict):
        raise ContractError("canonical contract and run-log schemas must be objects")
    _validate_contract_parity(contract, run_log_schema)

    goal = GoalSpec.from_dict(
        {
            "goal_id": "validation-goal",
            "target_outcome": "validate strict compiled contracts",
            "success_evidence_states": ["structure_verification"],
            "allowed_capabilities": [
                "read_local",
                "network",
                "external_download",
            ],
            "required_runtime_surfaces": [
                {
                    "surface_key": "repo-local",
                    "target_identity": "commit:validation",
                    "allowed_probes": ["git-head"],
                }
            ],
        }
    )
    task = TaskSpec.from_dict(
        {
            "task_id": "validation-task",
            "goal_id": "validation-goal",
            "objective": "parse the canonical task contract",
            "expected_delta": "quality",
            "primary_surface": "runtime-contracts.schema.json",
            "evidence_target": "structure_verification",
            "capabilities": ["read_local", "network", "external_download"],
            "integration_required": False,
            "required_runtime_surfaces": [
                {
                    "surface_key": "repo-local",
                    "target_identity": "commit:validation",
                    "allowed_probes": ["git-head"],
                }
            ],
        }
    )
    _validate_instance(
        validator_type,
        format_checker_type,
        validation_error_type,
        contract,
        goal.to_dict(),
        "compiled GoalSpec",
    )
    _validate_instance(
        validator_type,
        format_checker_type,
        validation_error_type,
        contract,
        task.to_dict(),
        "compiled TaskSpec",
    )
    instances_validated = 2

    timestamp = "2026-01-01T00:00:00Z"
    digest = "0" * 64
    limited_request = LimitedRulePromotionRequest(
        candidate_id="validation-candidate",
        candidate_digest=digest,
        policy_version="companyos-policy-v1",
        target_state="limited",
        source_run_id="validation-run",
        source_task_id="validation-task",
        verification_evidence_id="validation-evidence",
        verification_evidence_digest="6" * 64,
        verification_evidence_state="structure_verification",
        verification_evaluator_verdict="pass_with_residual_risk",
        promotion_validation_eval_id="validation-held-out",
        promotion_validation_dataset_digest="1" * 64,
        promotion_validation_attestation_digest="2" * 64,
        promotion_validation_query_count=1,
        promotion_validation_status="pass",
        scope="project://validation/prompt_candidate/bounded",
        actual_outcome_kind="failure_prevented",
        actual_outcome="the accepted claim documents one prevented failure",
        risk="residual validation risk remains bounded to this project",
        non_goals=("other projects", "business validation"),
        review_condition="review after one additional real task",
        rollback_or_retirement_path="retire validation candidate",
        non_claim_boundary="structure verification only",
    )
    limited_record = LimitedRulePromotionRecord(
        promotion_record_id="validation-limited-promotion",
        request=limited_request,
        from_state="owner_review",
        owner_approval_id="validation-limited-approval",
        owner_principal_id="validation-limited-owner",
        approved_at="2026-01-01T00:00:30Z",
    )
    _validate_instance(
        validator_type,
        format_checker_type,
        validation_error_type,
        contract,
        limited_request.to_dict(),
        "canonical LimitedRulePromotionRequest",
    )
    _validate_instance(
        validator_type,
        format_checker_type,
        validation_error_type,
        contract,
        limited_record.to_dict(),
        "canonical LimitedRulePromotionRecord",
    )
    instances_validated += 2
    custody_record = {
        "attestation_id": "validation-custody",
        "proposal_id": "validation-candidate",
        "eval_id": "validation-sealed",
        "project_id": "validation",
        "candidate_digest": digest,
        "dataset_digest": "4" * 64,
        "eval_attestation_digest": "5" * 64,
        "evaluator_principal_id": "validation-evaluator",
        "custody_provider": "validation-external-provider",
        "custodian_id": "validation-custodian",
        "policy_version": "companyos-policy-v1",
        "attestation_digest": "7" * 64,
        "verified_at": "2026-01-01T00:00:45Z",
    }
    _validate_instance(
        validator_type,
        format_checker_type,
        validation_error_type,
        contract,
        custody_record,
        "canonical SealedCustodyRecord",
    )
    instances_validated += 1
    promotion_record = ActiveRulePromotionRecord(
        promotion_record_id="validation-active-promotion",
        candidate_id="validation-candidate",
        candidate_digest=digest,
        policy_version="companyos-policy-v1",
        promotion_validation_eval_id="validation-held-out",
        promotion_validation_dataset_digest="1" * 64,
        promotion_validation_attestation_digest="2" * 64,
        promotion_validation_query_count=1,
        promotion_validation_status="pass",
        limited_promotion_record_id="validation-limited-promotion",
        limited_promotion_record_digest=content_hash(limited_record.to_dict()),
        source_task_id="validation-task",
        verification_evidence_id="validation-evidence",
        verification_evidence_digest="6" * 64,
        actual_outcome_kind="failure_prevented",
        actual_outcome="the accepted claim documents one prevented failure",
        from_state="limited",
        target_state="active",
        proposal_maker_principal_id="validation-maker",
        evaluator_principal_id="validation-evaluator",
        evaluator_digest="3" * 64,
        sealed_eval_id="validation-sealed",
        sealed_dataset_digest="4" * 64,
        sealed_dataset_use_count=1,
        sealed_result_influenced_edits=False,
        sealed_attestation_digest="5" * 64,
        sealed_custody_attestation_id="validation-custody",
        sealed_custody_provider="validation-external-provider",
        sealed_custodian_id="validation-custodian",
        sealed_custody_attestation_digest="7" * 64,
        sealed_custody_verified_at="2026-01-01T00:00:45Z",
        safety_hard_failures=0,
        eval_status="pass",
        evaluated_at=timestamp,
        owner_approval_id="validation-owner-approval",
        owner_principal_id="validation-owner",
        approved_at="2026-01-01T00:01:00Z",
        scope="project://validation/prompt_candidate/bounded",
        review_condition="review after one additional real task",
        non_goals=("human_acceptance", "business_validation"),
        rollback_or_retirement_path="retire validation candidate",
        non_claim_boundary="structure verification only",
    )
    _validate_instance(
        validator_type,
        format_checker_type,
        validation_error_type,
        contract,
        promotion_record.to_dict(),
        "canonical ActiveRulePromotionRecord",
    )
    instances_validated += 1

    wire_instances = (
        (
            "Lease",
            LeaseRecord(
                resource_key="repo://validation",
                project_id="validation-project",
                task_id="validation-task",
                holder="validation-worker",
                fence=1,
                issued_at=timestamp,
                expires_at="2026-01-01T00:05:00Z",
            ).to_wire(),
        ),
        (
            "OutboxEffect",
            OutboxEffect(
                effect_id="validation-effect",
                project_id="validation-project",
                run_id="validation-run",
                task_id="validation-task",
                step_id="validation-step",
                adapter="validation-adapter",
                idempotency_key="validation-key",
                request_digest=digest,
                status="authorization_pending",
                created_at=timestamp,
            ).to_wire(),
        ),
        (
            "EffectReceipt",
            EffectReceipt(
                receipt_id="validation-receipt",
                effect_id="validation-effect",
                status="succeeded",
                result={"validated": True},
                result_digest=digest,
                recorded_at=timestamp,
            ).to_wire(),
        ),
    )
    for schema_name, instance in wire_instances:
        wire_schema = {
            "$schema": DRAFT_2020_12,
            "$ref": f"#/$defs/{schema_name}",
            "$defs": contract["$defs"],
        }
        _validate_instance(
            validator_type,
            format_checker_type,
            validation_error_type,
            wire_schema,
            instance,
            f"canonical {schema_name} wire DTO",
        )
        instances_validated += 1

    for instance_name, schema_name in EXAMPLE_SCHEMA_PAIRS:
        _validate_instance(
            validator_type,
            format_checker_type,
            validation_error_type,
            documents[(repo / schema_name).resolve()],
            documents[(repo / instance_name).resolve()],
            instance_name,
        )
        instances_validated += 1

    run_log_instance = {
        "run_id": "validation-run",
        "started_at": "2026-01-01T00:00:00Z",
        "runtime_kit_version": "0.2.0.dev2",
        "project": "CompanyOS",
        "task_summary": "validate the compatibility run-log contract",
        "task_class": "contract_validation",
        "evidence_state": "structure_verification",
        "verification": [{"command": "validate", "status": "passed"}],
        "non_claims": list(STRUCTURE_VALIDATION_NON_CLAIMS),
        "integration_queue_state": "ci_failed",
    }
    _validate_instance(
        validator_type,
        format_checker_type,
        validation_error_type,
        run_log_schema,
        run_log_instance,
        "synthetic compatibility run log",
    )
    instances_validated += 1

    obsolete = [
        "runtime/taskrun-log.schema.json",
        "templates/TASK_STARTUP_PACKET.md",
    ]
    stale = [name for name in obsolete if (repo / name).exists()]
    if stale:
        raise ContractError(f"retired duplicate surfaces are still active: {stale}")

    _validate_compatibility_manifest(repo)

    return {
        "repository": str(repo),
        "required_files": len(REQUIRED_FILES),
        "json_files_parsed": len(documents),
        "draft_2020_12_schemas_checked": schema_count,
        "contract_definitions": len(contract["$defs"]),
        "instances_validated": instances_validated,
        "status": "passed",
        "evidence_state": "structure_verification",
        "non_claims": list(STRUCTURE_VALIDATION_NON_CLAIMS),
    }
