"""SQLite schema for the single-host durable runtime implementation."""

SCHEMA_VERSION = 5

DDL = r"""
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    checksum TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS principals (
    principal_id TEXT PRIMARY KEY,
    principal_key TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    credential_salt BLOB NOT NULL,
    credential_hash BLOB NOT NULL,
    credential_iterations INTEGER NOT NULL CHECK (credential_iterations >= 100000),
    credential_version INTEGER NOT NULL DEFAULT 1 CHECK (credential_version > 0),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    disabled_at TEXT
);

CREATE TABLE IF NOT EXISTS principal_roles (
    principal_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (
        role IN (
            'owner', 'worker', 'evaluator', 'release', 'observer',
            'provider_attestor', 'human_acceptor', 'business_reviewer',
            'system'
        )
    ),
    granted_at TEXT NOT NULL,
    PRIMARY KEY (principal_id, role),
    FOREIGN KEY (principal_id) REFERENCES principals(principal_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS authenticated_sessions (
    session_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    session_token_hash BLOB NOT NULL UNIQUE,
    credential_version INTEGER NOT NULL CHECK (credential_version > 0),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    CHECK (expires_at > issued_at),
    FOREIGN KEY (principal_id) REFERENCES principals(principal_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_authenticated_sessions_principal
    ON authenticated_sessions(principal_id, expires_at);

CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    aggregate_version INTEGER NOT NULL CHECK (aggregate_version > 0),
    project_id TEXT NOT NULL,
    run_id TEXT,
    task_id TEXT,
    event_type TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    actor TEXT NOT NULL,
    auth_context_json TEXT NOT NULL,
    command_id TEXT NOT NULL,
    idempotency_key TEXT,
    correlation_id TEXT NOT NULL,
    causation_id TEXT,
    policy_version TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    confidentiality TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    UNIQUE (aggregate_type, aggregate_id, aggregate_version),
    FOREIGN KEY (causation_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_events_aggregate
    ON events(aggregate_type, aggregate_id, aggregate_version);
CREATE INDEX IF NOT EXISTS idx_events_run_task ON events(run_id, task_id, seq);

CREATE TRIGGER IF NOT EXISTS events_authorized_insert
BEFORE INSERT ON events BEGIN
    SELECT CASE
        WHEN companyos_event_insert_authorized(NEW.event_id, NEW.event_hash) = 1
        THEN 1
        ELSE RAISE(ABORT, 'event inserts require store command authority')
    END;
END;

CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TABLE IF NOT EXISTS idempotency_records (
    project_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    result_json TEXT NOT NULL,
    event_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, scope, idempotency_key),
    FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE TABLE IF NOT EXISTS goals (
    goal_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    state TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    aggregate_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS adopted_projects (
    project_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL CHECK (version > 0),
    digest TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    current_program_id TEXT NOT NULL,
    adopted_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS adopted_programs (
    program_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    digest TEXT NOT NULL,
    state TEXT NOT NULL,
    graph_digest TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    adopted_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES adopted_projects(project_id)
);

CREATE TABLE IF NOT EXISTS goal_authority_bindings (
    goal_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    program_id TEXT NOT NULL,
    authority_digest TEXT NOT NULL,
    authority_json TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    FOREIGN KEY (goal_id) REFERENCES goals(goal_id),
    FOREIGN KEY (program_id) REFERENCES adopted_programs(program_id),
    FOREIGN KEY (source_event_id) REFERENCES events(event_id)
);

CREATE TABLE IF NOT EXISTS task_authority_bindings (
    task_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    program_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    authority_digest TEXT NOT NULL,
    authority_json TEXT NOT NULL,
    provider_budget_minor_units INTEGER NOT NULL CHECK (provider_budget_minor_units >= 0),
    provider_call_limit INTEGER NOT NULL CHECK (provider_call_limit >= 0),
    required_decision_gates_json TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id),
    FOREIGN KEY (goal_id) REFERENCES goal_authority_bindings(goal_id),
    FOREIGN KEY (source_event_id) REFERENCES events(event_id)
);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    goal_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    loop_state TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    aggregate_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (goal_id) REFERENCES goals(goal_id)
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    goal_id TEXT NOT NULL,
    run_id TEXT,
    project_id TEXT NOT NULL,
    state TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    aggregate_version INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    due_at TEXT,
    last_error_fingerprint TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (goal_id) REFERENCES goals(goal_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_tasks_queue ON tasks(project_id, state, due_at);

CREATE TABLE IF NOT EXISTS attempts (
    attempt_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    worker_id TEXT NOT NULL,
    state TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    failure_id TEXT,
    UNIQUE(task_id, attempt_number),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS workflow_steps (
    task_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    status TEXT NOT NULL,
    input_digest TEXT NOT NULL,
    result_json TEXT,
    effect_id TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY (task_id, step_id),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

CREATE TABLE IF NOT EXISTS leases (
    resource_key TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    holder TEXT NOT NULL,
    fence INTEGER NOT NULL CHECK (fence > 0),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    released_at TEXT,
    CHECK (expires_at > issued_at),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    requester TEXT NOT NULL,
    approver TEXT,
    capability TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    decision TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    decided_at TEXT,
    expires_at TEXT,
    FOREIGN KEY (goal_id) REFERENCES goals(goal_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

CREATE TABLE IF NOT EXISTS capability_grants (
    grant_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    goal_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    approval_id TEXT,
    issuer TEXT NOT NULL,
    principal TEXT NOT NULL,
    capability TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    not_before TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_uses INTEGER NOT NULL CHECK (max_uses > 0),
    used_count INTEGER NOT NULL DEFAULT 0 CHECK (used_count >= 0),
    cost_limit INTEGER NOT NULL DEFAULT 0 CHECK (cost_limit >= 0),
    cost_used INTEGER NOT NULL DEFAULT 0 CHECK (cost_used >= 0),
    required_fence INTEGER,
    revoked_at TEXT,
    CHECK (expires_at > not_before),
    FOREIGN KEY (approval_id) REFERENCES approvals(approval_id),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

CREATE TABLE IF NOT EXISTS capability_usage (
    grant_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    cost INTEGER NOT NULL CHECK (cost >= 0),
    used_at TEXT NOT NULL,
    effect_id TEXT,
    PRIMARY KEY (grant_id, idempotency_key),
    FOREIGN KEY (grant_id) REFERENCES capability_grants(grant_id)
);

CREATE TABLE IF NOT EXISTS outbox (
    effect_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    adapter TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    dispatched_at TEXT,
    reconciled_at TEXT,
    last_error TEXT,
    UNIQUE(project_id, idempotency_key),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

CREATE TABLE IF NOT EXISTS effect_receipts (
    receipt_id TEXT PRIMARY KEY,
    effect_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    provider_receipt TEXT,
    result_json TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (effect_id) REFERENCES outbox(effect_id)
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    producer_principal_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    uri TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    confidentiality TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id),
    FOREIGN KEY (producer_principal_id) REFERENCES principals(principal_id)
);

CREATE TABLE IF NOT EXISTS evidence_claims (
    evidence_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    claim TEXT NOT NULL,
    evidence_state TEXT NOT NULL,
    artifact_refs_json TEXT NOT NULL,
    verifier_principal_id TEXT NOT NULL,
    verifier_version TEXT NOT NULL,
    environment TEXT NOT NULL,
    evaluator_verdict TEXT NOT NULL,
    non_claims_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id),
    FOREIGN KEY (verifier_principal_id) REFERENCES principals(principal_id)
);

CREATE TABLE IF NOT EXISTS runtime_observations (
    observation_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    surface_key TEXT NOT NULL,
    target_identity TEXT NOT NULL,
    observer TEXT NOT NULL,
    probe_name TEXT NOT NULL,
    probe_version TEXT NOT NULL,
    trigger_event_id TEXT,
    status TEXT NOT NULL,
    value_json TEXT NOT NULL,
    value_digest TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    UNIQUE(run_id, surface_key, observation_id),
    CHECK (expires_at > observed_at),
    FOREIGN KEY (trigger_event_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_observations_fresh
    ON runtime_observations(run_id, surface_key, expires_at);

CREATE TABLE IF NOT EXISTS context_items (
    context_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    content TEXT NOT NULL,
    classification TEXT NOT NULL,
    normative_status TEXT NOT NULL,
    priority INTEGER NOT NULL,
    token_estimate INTEGER NOT NULL CHECK (token_estimate >= 0),
    observed_at TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    expires_at TEXT,
    supersedes TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (supersedes) REFERENCES context_items(context_id)
);

CREATE TABLE IF NOT EXISTS context_assemblies (
    assembly_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    token_budget INTEGER NOT NULL,
    selected_json TEXT NOT NULL,
    rejected_json TEXT NOT NULL,
    assembly_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

CREATE TABLE IF NOT EXISTS memory_items (
    memory_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    source_evidence_id TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    scope TEXT NOT NULL,
    classification TEXT NOT NULL,
    content TEXT NOT NULL,
    status TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    expires_at TEXT,
    supersedes TEXT,
    promotion_approval_id TEXT,
    heldout_eval_id TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (source_evidence_id) REFERENCES evidence_claims(evidence_id),
    FOREIGN KEY (supersedes) REFERENCES memory_items(memory_id),
    FOREIGN KEY (promotion_approval_id) REFERENCES approvals(approval_id)
);

CREATE TABLE IF NOT EXISTS negative_results (
    failure_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    failure_class TEXT NOT NULL,
    severity TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    repair_route TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    recurrence_count INTEGER NOT NULL DEFAULT 1 CHECK (recurrence_count > 0),
    expires_at TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

CREATE TABLE IF NOT EXISTS eval_runs (
    eval_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    candidate_digest TEXT NOT NULL,
    dataset_name TEXT NOT NULL,
    dataset_split TEXT NOT NULL,
    dataset_digest TEXT NOT NULL,
    evaluator TEXT NOT NULL,
    evaluator_version TEXT NOT NULL,
    status TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    safety_failures_json TEXT NOT NULL,
    attestation_id TEXT NOT NULL UNIQUE,
    attestation_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS improvement_proposals (
    proposal_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    source_run_id TEXT NOT NULL,
    hypothesis TEXT NOT NULL,
    candidate_digest TEXT NOT NULL,
    editable_surface TEXT NOT NULL,
    expected_benefit TEXT NOT NULL,
    risk TEXT NOT NULL,
    rollback_route TEXT NOT NULL,
    held_in_eval_id TEXT,
    held_out_eval_id TEXT,
    sealed_eval_id TEXT,
    state TEXT NOT NULL,
    owner_approval_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (held_in_eval_id) REFERENCES eval_runs(eval_id),
    FOREIGN KEY (held_out_eval_id) REFERENCES eval_runs(eval_id),
    FOREIGN KEY (sealed_eval_id) REFERENCES eval_runs(eval_id),
    FOREIGN KEY (owner_approval_id) REFERENCES approvals(approval_id)
);

CREATE TABLE IF NOT EXISTS sealed_custody_attestations (
    attestation_id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL UNIQUE,
    eval_id TEXT NOT NULL UNIQUE,
    project_id TEXT NOT NULL,
    candidate_digest TEXT NOT NULL,
    dataset_digest TEXT NOT NULL,
    eval_attestation_digest TEXT NOT NULL,
    evaluator_principal_id TEXT NOT NULL,
    custody_provider TEXT NOT NULL,
    custodian_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    attestation_digest TEXT NOT NULL UNIQUE,
    verified_at TEXT NOT NULL,
    FOREIGN KEY (proposal_id) REFERENCES improvement_proposals(proposal_id),
    FOREIGN KEY (eval_id) REFERENCES eval_runs(eval_id)
);

CREATE TABLE IF NOT EXISTS integration_items (
    integration_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    state TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    owner TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);
"""
