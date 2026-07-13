# CompanyOS

CompanyOS is a public-safe, single-host operating runtime for AI-native
software work. It combines human-readable Goal Contracts and Task Packets with
a code-enforced Runtime Kernel: durable events, explicit state machines,
task-scoped capability grants, leases and fencing, a transactional outbox,
typed evidence, runtime freshness, integration/evaluation queues, scoped
context and memory, and guarded self-improvement proposals.

It is not the private COS source vault, a generic skill library, a
project-specific submodule, a distributed workflow engine, or proof of
provider/human/business acceptance. GFR is the authoring-to-runtime compiler
boundary inside CompanyOS. Codex is one adapter, not the repository identity.

## What Is Executable

```mermaid
flowchart LR
    A["Goal Contract / Task Packet"] --> B["Goal Compiler"]
    B --> C["Strict GoalSpec / TaskSpec"]
    C --> D["Runtime Kernel"]
    D --> E["Event ledger + projections"]
    D --> F["Lease + exact capability grant"]
    F --> G["Outbox + idempotent adapter"]
    G --> H["Evidence + evaluator + integration + freshness"]
    H --> I["Authoritative delivery guard"]
```

The kernel is implemented in `companyos_runtime/`. The canonical wire
contracts are in `runtime/contracts/v1/runtime-contracts.schema.json`. The
architecture and operational limits are documented in:

- `docs/runtime-architecture.md`
- `docs/operations-runbook.md`

## Quick Start

Python 3.11 or newer is required.

```powershell
python -m pip install -e .
python -m companyos_runtime --db "$HOME/.company-os/state/runtime.db" init
python -m companyos_runtime validate --repo .
```

Run the complete zero-provider-cost crash/recovery slice:

```powershell
python -m companyos_runtime demo `
  --state-dir "$HOME/.company-os/demos/crash-recovery" `
  --fault-at after_effect_before_checkpoint
```

The demo creates a Goal/Run/Task, acquires a fenced lease, records a
maker-checker approval and exact zero-cost grant, performs one idempotent effect
against a separate fake-provider ledger, crashes before checkpoint, reconciles
the receipt, records independent runtime evidence and a fresh observation,
closes Integration Queue, verifies replay, and routes an improvement candidate
through held-in and isolated held-out evaluation. It stops at owner review.

Expected scoped claims:

```text
run_state = delivered
task_state = delivered
external_effect_delta = 1
evidence_state = runtime_verification
improvement_state = owner_review
provider_cost = 0
```

It does not claim provider smoke, human acceptance, business/legal validation,
public release, active-rule promotion, or multi-host exactly-once behavior.

## Runtime Invariants

- Goal/Task authority is strict and segment-safe; TaskSpec must be a subset of
  GoalSpec.
- Run transitions are event driven; direct LoopState mutation is rejected.
- Delivery guards are computed from persisted evidence, evaluator,
  Integration Queue, and fresh observations. Caller booleans are not authority.
- Approvals require different maker/checker principals. Grants bind principal,
  task, capability, action, resource, request digest, expiry, use count, budget,
  and optional fencing token. Approval, issue, and consume also recheck that the
  exact resource remains inside the persisted TaskSpec scope and outside every
  forbidden scope. Each capability has a closed action vocabulary, and
  approval/grant/consume obey capability-specific execution phases.
- Scheduler order is explicit: claim while the Run is ready, prove the exact
  lease holder/fence through the Run `task_started` event, then start the Task.
  Worker consumption also requires a current `task://<task_id>` claim; stale
  or terminal work cannot create a new external effect. Enqueue preflights the
  live holder and exact grant before reserving a declared workflow step.
- Event payloads are digest-verified and globally hash chained. Core
  Goal/Run/Task events also require a live authenticated session,
  event-specific role, and per-store opaque command capability bound to the
  exact RuntimeKernel or TaskScheduler instance; caller handler metadata is
  rejected. Approval, artifact/evidence, evaluation/improvement, and sealed
  custody authority events likewise require an opaque capability bound to the
  exact trusted service instance and its configuration digest. All store
  objects for the same resolved database path share one process-local authority
  domain; only one live EvaluationRegistry may hold its verifier authority, and
  verifier implementation types/configuration stay pinned. Projections can be
  replayed and checked. Schema v4 also rejects direct event-table inserts unless
  the exact event ID/hash was armed by `SQLiteStore.append_event` on that
  managed connection.
- Synthetic evidence cannot be upgraded to provider, human, business, memory,
  or active-rule evidence.
- Context records selection and rejection. Memory promotion preserves evidence
  provenance, TTL, promotion-validation, and exact human approval.
- Candidate-to-limited rule promotion requires a canonical
  `LimitedRulePromotionRecord`: the source Run and Task are both durably
  delivered, the exact structure/runtime claim has a `pass` or
  `pass_with_residual_risk` verdict and a typed `accepted_evidence_id` Task
  event, the documented actual outcome equals that claim, and bounded scope,
  risk, non-goals, review condition, and rollback are all included in the
  Owner approval digest. A single typed provenance classifier canonicalizes
  case, Unicode, whitespace/underscore aliases, and nested percent encoding;
  non-real or unknown environment, artifact kind, or URI scheme is rejected by
  this gate.
- Active rule promotion is separate from durable memory promotion and is never
  automatic; active promotion also requires a sealed evaluation that was not
  used to select the candidate plus a separately verified external-custody
  attestation. The custody verifier defaults to deny. Canonical readback
  verifies the exact limited record, custody provider/custodian/digest, and the
  full proposal/eval/approval event lineage in one transaction snapshot.

Opaque capabilities are an in-process boundary, not a claim against hostile
reflection/monkey-patching or a compromised host/SQLite administrator. Those
actors remain in the trusted computing base and require OS, process, key, and
external attestation controls outside this runtime.

## Authoring and Compilation

Use these public-safe authoring templates:

```text
templates/AOS_STARTUP_PACKET.md
templates/GOAL_CONTRACT.md
templates/TASK_PACKET.md
templates/EVIDENCE_PACKET.md
templates/RUNTIME_SURFACE_VECTOR.md
```

Compile JSON authoring packets before execution:

```powershell
python -m companyos_runtime compile-goal --input goal-authoring.json
python -m companyos_runtime compile-task `
  --input task-authoring.json --goal-spec compiled-goal.json
```

Narrative fields such as worker preference, worktree choice, and handoff notes
remain contextual. Only the compiled spec is executable authority.
Each executable workflow step binds `step_id`, adapter, action, resource, and
the SHA-256 digest of the exact request; enqueue and dispatch both revalidate
that persisted declaration.

The accepted authoring shape is closed by
`runtime/contracts/v1/authoring-contracts.schema.json`. Complete Goal and Task
fixtures live under `examples/authoring/`. The compiler, schemas, templates,
and fixtures are frozen together by
`runtime/contracts/v1/compatibility-manifest.json`; repository validation fails
if one of those artifacts drifts without a manifest update.

## Local CLI

```powershell
# Redacted counts and one run projection
python -m companyos_runtime --db .state/runtime.db status --run-id run-1

# Hash chain plus deterministic core replay
python -m companyos_runtime --db .state/runtime.db verify

```

Create a verified online backup, restore it only into a new target, and inspect
a redacted operator snapshot:

```powershell
python -m companyos_runtime --db .state/runtime.db backup `
  --target .backups/runtime-001.db
python -m companyos_runtime restore `
  --backup .backups/runtime-001.db `
  --target .restore-tests/runtime.db
python -m companyos_runtime `
  --db .restore-tests/runtime.db operator-snapshot
```

The manifest verifies SQLite integrity, the event chain, and core projection
replay/readback. It deliberately marks the recovery set incomplete: external
adapter receipt/idempotency ledgers must be backed up separately. Restore
refuses every existing target or SQLite sidecar. Operator output is limited to
counts, digests, and freshness; it is not process or provider health.

Run the bundled zero-cost adapter conformance report:

```powershell
python -m companyos_runtime adapter-conformance `
  --state-dir .state/adapter-conformance
```

Project adapters can implement the public `WorkflowAdapter` protocol and use
the reusable harness described in `docs/adapter-conformance.md`.

Run the AOS Core v0.1 cross-domain handoff harness with the bundled CompanyOS
and AgentFlow Studio deterministic fixtures:

```powershell
python -m companyos_runtime domain-pack-conformance `
  --fixture tests/fixtures/domain_packs/companyos.json `
  --fixture tests/fixtures/domain_packs/agentflow-studio.json
```

The Core object and Domain Pack boundary are defined in
`docs/aos-core-v0.1.md`.

Mutating runtime commands, outbox recovery, and projection repair are not
exposed as unauthenticated CLI surfaces in v0.2. An embedding application must
authenticate an opaque session and invoke the relevant Python service inside
the trusted kernel process.

The PowerShell compatibility adapter retains the old draft/log commands and
routes runtime validation to the Python kernel:

```powershell
.\bin\company-os.ps1 validate
.\bin\company-os.ps1 runtime-demo -StateDir "$HOME/.company-os/demos/demo-1"
.\bin\company-os.ps1 runtime-status
.\bin\company-os.ps1 runtime-verify
```

## Repository Layout

```text
companyos_runtime/    executable kernel and CLI
runtime/contracts/    canonical public wire contracts
core/                 authority and evidence doctrine
gfr/                  startup/compiler contract
full-stack/           engineering and release standards
templates/            human authoring packets
adapters/              runtime-specific guidance; Codex is one adapter
docs/                  architecture, operations, source sync, onboarding
tests/                 contract, concurrency, chaos, policy, evidence and eval tests
.github/workflows/      Windows and Ubuntu structure-verification CI
```

## Install Boundary

`install.ps1` and `install.sh` install only into a managed, marked directory.
They refuse recursive replacement of an unmarked path. Runtime state lives
outside the installed kit under `~/.company-os/state`; reinstalling code does
not authorize or erase unrelated project state.

Cloning or installing CompanyOS cannot alter every project on a machine. Each
project must opt in and compile its own Goal/Task authority. Remote repository
mutation, server writes, provider cost, destructive cleanup, public release,
human acceptance, legal/business decisions, and active-rule promotion always
remain separately gated.
