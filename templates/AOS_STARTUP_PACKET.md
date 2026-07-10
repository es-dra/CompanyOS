# AOS Startup Packet

Use this at the start of a substantial project task. Keep the filled packet
compact and load deeper templates only when the selected profile needs them.

```yaml
aos_startup_packet:
  packet_id:
  date:
  identity_lens:
  primary_profile: light | standard | deep | program | strategic
  owner_intent:
  target_outcome:
  authority:
    read_scope: []
    write_scope: []
    forbidden_scope: []
  required_reads: []
  project_capsule:
  runtime_surfaces: []
  tool_provider_gates:
    read_local:
    write_local:
    repo_remote:
    server_read:
    server_write:
    provider_cost:
    public_release:
    destructive:
  evidence_target:
  forbidden_claims: []
  task_packet_required: true | false
  evaluator_policy:
  integration_policy:
  stop_conditions: []
  first_action:
  closeout_shape:
```

## Minimal Intake

Ask only for fields that change execution:

```text
target outcome
allowed writes
forbidden writes
acceptance signal
provider/server/public/destructive authority
```
