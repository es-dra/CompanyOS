# Goal Contract

Use this authoring packet for substantial work. The Goal Compiler must reduce
it to the strict `GoalSpec` below before Runtime Kernel execution. Authoring
metadata is useful context; it is not executable authority by itself.

## Human authoring packet

```yaml
goal_contract:
  goal_id:
  source_request:
  target_outcome:
  success_evidence_states:
    - structure_verification
    # Add only levels genuinely required by this goal:
    # runtime_verification | provider_smoke | human_acceptance |
    # business_validation | durable_memory_promotion | active_rule_promotion
  non_goals: []
  owner_authority:
    read_scope: []
    write_scope: []
    forbidden_scope: []
    allowed_capabilities:
      - read_local
    # Optional: write_local | network | external_download | repo_remote |
    # server_read | server_write | provider_cost | public_release | destructive |
    # durable_memory_promotion | active_rule_promotion | control_resume
  required_runtime_surfaces:
    - surface_key: repo-local
      target_identity: commit:<expected-sha>
      allowed_probes: [git-head]
      max_ttl_seconds: 300
      trigger_event_required: true
  context_pack:
  project_adoption_ref:
  evaluator_required: false
  integration_policy:
  circuit_breakers:
    max_iterations_without_new_evidence: 3
    provider_budget:
      currency: USD
      max_minor_units: 0
      max_calls: 0
  stop_routes:
    - suspend_for_input
    - evaluator_gate
    - integration_queue
    - delete_or_retire
    - rewrite_task
    - split_goal
    - blocked_with_decision
```

## Compiled GoalSpec

The executable JSON object uses only these fields and rejects unknown keys:

```json
{
  "goal_id": "goal-1",
  "target_outcome": "a precise outcome",
  "success_evidence_states": ["runtime_verification"],
  "read_scope": ["repo://project"],
  "write_scope": ["repo://project/worktree"],
  "forbidden_scope": ["server://production"],
  "allowed_capabilities": ["read_local", "write_local"],
  "required_runtime_surfaces": [],
  "evaluator_required": true,
  "max_iterations_without_evidence": 3,
  "provider_budget_minor_units": 0,
  "provider_call_limit": 0,
  "budget_currency": "USD",
  "non_goals": ["provider_smoke", "human_acceptance"]
}
```

`durable_memory_promotion` is an evidence/capability path for scoped memory.
`active_rule_promotion` is a separate capability and must never be inferred
from memory promotion or a successful demo.
