# AOS Core v0.1 and Domain Pack Boundary

Status: executable candidate contract. It is local runtime evidence, not a
public standard or an active Company OS rule.

## Smallest Core

AOS Core v0.1 accepts one strict handoff object:

```text
AOSCoreBundle
  contract_version = aos.core.v0.1
  domain_pack = pack id + version
  domain_ref = opaque domain-owned URI
  goal_spec = compiled GoalSpec
  task_spec = compiled TaskSpec bounded by GoalSpec
  source_digests = authoring provenance
```

The executable object is `companyos_runtime.domain_packs.AOSCoreBundle`; its
wire shape is `runtime/contracts/v1/aos-core-v0.1.schema.json`.

Core owns authority bounds, capabilities, evidence target, runtime-surface
requirements, workflow step identity/digest, retry bound, evaluator flag, and
integration requirement. Core rejects unknown fields and verifies that TaskSpec
does not exceed GoalSpec.

## Domain Pack API

A Domain Pack supplies only:

```python
pack_id
pack_version
domain
domain_ref
goal_authoring() -> Mapping
task_authoring() -> Mapping
```

The pack translates domain state into Core authoring objects. Scripts,
storyboards, customer data, provider payloads, media, governance source text,
and domain lifecycle state remain behind the opaque `domain_ref`. Workflow
adapter ids must be namespaced by `pack_id`; request bodies remain outside Core
and enter only as SHA-256 digests.

## Cross-Domain Evidence

The deterministic fixtures represent two different domains:

- CompanyOS: bounded public-safe projection review;
- AgentFlow Studio: script artifact to reviewable storyboard candidate, with
  provider/server gates closed and an evaluator required before claim.

Run:

```powershell
python -m companyos_runtime domain-pack-conformance `
  --fixture tests/fixtures/domain_packs/companyos.json `
  --fixture tests/fixtures/domain_packs/agentflow-studio.json
```

The harness proves strict compilation, task-within-goal authority, adapter
namespace isolation, opaque domain references, deterministic recompilation,
and strict bundle roundtrip for both domains.

## v0.1 Exit-Gap Matrix

| Gap | Current evidence | Exit evidence |
|---|---|---|
| Real project adapter adoption | deterministic fixtures only | one isolated real adapter per domain passes the harness |
| Runtime kernel execution | compiled bundle and roundtrip | kernel consumes the bundle through a stable submission API |
| Recovery across domain state | source digests and domain ref only | domain state plus Core receipts survive crash/replay tests |
| Multi-host delivery | excluded | lease, fencing, and reconciliation evidence across hosts |
| Provider behavior | gates closed | separately authorized provider smoke and failure matrix |
| Human/media quality | explicitly excluded | independent human-quality evaluation on real deliverables |
| Business validation | explicitly excluded | real customer or commercial evidence |
| Public standard / active rule | candidate contract only | separate owner review and promotion/publication decision |

Do not close these gaps with governance prose or CI alone.
