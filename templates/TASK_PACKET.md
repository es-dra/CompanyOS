# Task Packet

A Task Packet is the bounded executable unit. A thread, worker, automation, or
worktree is only the selected execution resource. The Goal Compiler must emit a
strict `TaskSpec`; narrative fields are not grants.

## Human authoring packet

```yaml
task_packet:
  task_id:
  parent_goal_id:
  objective:
  expected_delta: product | quality | governance | runtime | integration | blocker_reduction
  primary_artifact_or_surface:
  read_scope: []
  write_scope: []
  forbidden_scope: []
  dirty_boundary: []
  worktree_policy: current_checkout | create_worktree | use_existing_worktree | read_only
  worker_policy: main_thread | worker_allowed | worker_required | no_worker
  capabilities:
    - read_local
  evaluator_policy: not_required | required_before_integration | required_before_claim
  integration_required: true
  required_runtime_surfaces:
    - surface_key: repo-local
      target_identity: commit:<expected-sha>
      allowed_probes: [git-head]
      max_ttl_seconds: 300
      trigger_event_required: true
  gates:
    network:
    provider:
    external_download:
    destructive_operations:
    repo_remote:
    server_write:
    public_release:
  workflow_steps:
    - step_id:
      adapter:
      action:
      resource:
      request_digest: # lowercase SHA-256 of the exact request object
  verification_route: []
  evidence_target:
  integration_route:
  max_attempts: 3
  stop_conditions: []
  close_condition:
  non_claims: []
```

## Compiled TaskSpec

```json
{
  "task_id": "task-1",
  "goal_id": "goal-1",
  "objective": "produce a bounded verified delta",
  "expected_delta": "runtime",
  "primary_surface": "repo://project/worktree",
  "evidence_target": "runtime_verification",
  "capabilities": ["read_local", "write_local"],
  "read_scope": ["repo://project"],
  "write_scope": ["repo://project/worktree"],
  "forbidden_scope": ["server://production"],
  "required_runtime_surfaces": [],
  "evaluator_required": true,
  "integration_required": true,
  "workflow_steps": [
    {
      "step_id": "verify-local-runtime",
      "adapter": "local",
      "action": "write",
      "resource": "repo://project/worktree",
      "request_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ],
  "max_attempts": 3
}
```

The runtime rejects a TaskSpec whose goal identity, capability, scope, or
runtime surfaces exceed its parent GoalSpec.
