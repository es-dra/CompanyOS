# CompanyOS Runtime Migration v0.2 Draft

Status: implementation and migration plan, pre-release. The migration keeps
the existing document workflow usable while moving execution authority into the
Runtime Kernel.

## Object Decisions

| Object | Decision | Reason |
|---|---|---|
| CompanyOS public identity | Keep | Correct distribution boundary; not a private source dump or project submodule |
| GFR | Rewrite as compiler boundary | Authoring packets must compile to strict runtime contracts |
| AOS Startup Packet | Keep as authoring context | Useful intake; not direct runtime authority |
| Goal Contract / Task Packet | Keep authoring form plus compiled form | Human usability and machine enforcement serve different audiences |
| Goal projection lifecycle | Reduce to immutable `compiled` | Run and Task own executable progress; multi-run Goal aggregation is undefined in v0.2, so additional Goal states would be phantom authority |
| Event ledger and core projections | Add | Durable state, optimistic concurrency, audit and replay |
| Caller-provided transition guards | Delete as authority | Persisted facts must decide transitions |
| Heartbeat status cadence | Reduce to monitor trigger | A valid tick must advance, evaluate, integrate, retire, or request a decision |
| Local JSON run logs | Retain as compatibility/export only | They are evidence inputs, not canonical execution state |
| `runtime/taskrun-log.schema.json` | Delete | Superseded duplicate of the AOS run log |
| `templates/TASK_STARTUP_PACKET.md` | Delete | Superseded by AOS Startup Packet plus Task Packet |
| `durable_rule_promotion` label | Delete from active contracts | Ambiguous; split into durable memory and active-rule promotion |
| Runtime Surface Vector | Keep and enforce through observations | Documentation alone cannot close drift |
| Integration Queue | Rewrite as durable state machine | Merge/deploy/restart/freshness/delete/retire must not collapse |
| Improvement Queue | Rewrite as protected proposal/eval pipeline | No automatic authority or active-rule mutation |
| Context/memory | Add lifecycle ledgers | Scope, classification, TTL, provenance, supersession and held-out promotion |
| Worker/evaluator lanes | Keep as temporary resources | Require bounded scope, evidence, and close conditions |

## Migration Sequence

### M0 — Isolate and inventory

- create a dedicated worktree and branch when isolation is required;
- preserve unrelated dirty changes;
- record concurrent writers and declare their writable surfaces out of scope;
- record servers, providers, remote repositories, and ports as separate runtime
  surfaces when they are relevant;
- run tests and validators before changing semantics.

Exit: no competing task is touched; baseline hashes and dirty state are known.

### M1 — Establish the kernel

- strict GoalSpec/TaskSpec and segment-safe scope containment;
- immutable compiled Goal projection, event-driven Run state machine, and
  executable Task projection state machine;
- append-only hash-chained events and deterministic core replay;
- SQLite WAL/FULL single-host store and idempotency records;
- leases, monotonic fences, maker-checker approvals, exact grants and budgets.

Exit: concurrency, tampering, idempotency, and state-transition tests pass.
No delivery, deletion, retirement, or blocking claim is inferred at Goal level
until a later version defines and implements multi-run aggregation semantics.

### M2 — Close the delivery loop

- transactional outbox and receipt reconciliation;
- typed artifacts/evidence and evidence-level anti-inflation;
- fresh runtime observations;
- durable Integration Queue;
- authoritative Guard Resolver;
- negative-result retention and bounded scheduler primitives.

Exit: caller `true` cannot override an incomplete queue; crash matrix recovers
one fake external effect with zero provider cost.

### M3 — Context, memory and improvement

- context selection/rejection trace and token budget;
- memory candidate/provenance/TTL/supersession lifecycle;
- discovery, isolated promotion-validation, then sealed-test evaluation;
- protected self-improvement surfaces;
- separate durable-memory and active-rule approvals.

Exit: held-out leakage, changed provenance, safety failure, wrong capability,
and direct active jump all fail closed.

### M4 — Compatibility and public projection

- keep human authoring templates and legacy draft/log commands;
- route validation/runtime commands to the Python kernel;
- install into a managed marked directory without deleting arbitrary paths;
- update architecture, operations, contracts, onboarding and source-sync docs;
- keep private source details, project secrets, provider responses and real
  operational data out of the public projection.

Exit: full tests, repository validation, PowerShell syntax, install safety and
`git diff --check` pass.

### M5 — Shadow adoption

- select a non-critical project that is not under an active competing task;
- import read-only project/runtime surfaces;
- compile a real Goal/Task but keep write/provider/server/remote capabilities
  closed;
- compare manual decisions with Guard Resolver output;
- run replay, backup/restore and 24–72 hour scheduler/reaper soak tests.

Exit: no authority drift, missed stale surface, duplicate effect, lost negative
result, or unbounded context growth.

### M6 — Bounded local-write pilot

- open one local worktree resource with exact grant and fence;
- require independent evaluator and Integration Queue closure;
- compare rollback and recovery against the existing manual workflow;
- select a project surface with no concurrent writer.

Exit: pilot meets the evaluation plan and owner accepts the handoff boundary.

### M7 — Remote/server/provider adapters

Enable one capability at a time. Each adapter needs idempotency or
reconciliation, redaction, cost accounting in integer minor units, bounded
retry, circuit breaker, fresh observation, independent evaluation, and a
rollback route. No capability opens because a previous capability succeeded.

## Rollback

- The old human templates and draft/export commands remain available.
- Runtime code is isolated in `companyos_runtime/` and state under
  `~/.company-os/state`.
- Disable runtime adoption by removing the project opt-in; do not delete the
  evidence DB during rollback.
- Preserve events, receipts, observations, evals, negative results and migration
  decisions for audit.
- Revert code through Git; restore runtime state only from a verified backup.
