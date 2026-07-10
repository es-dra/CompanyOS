# CompanyOS Runtime Evaluation Plan v0.2 Draft

Status: executable baseline plus release/soak plan. Passing one demo is not a
maturity claim.

## Release Gates

| Gate | Required evidence | Primary failure examples |
|---|---|---|
| G0 Contract | strict parsing, unknown-field rejection, Goal/Task containment | ambiguous authority, scope traversal, identity mismatch |
| G1 State | declared transitions pass; every undeclared pair fails | direct delivery, terminal restart, failed-as-terminal |
| G2 Integrity | event hash/payload/causation/version/replay checks | event edit/delete, projection drift, idempotency conflict |
| G3 Identity/policy | authenticated session/role, maker-checker, closed capability/action map, phase-bound exact grant, expiry/revoke/use/budget/task-claim/fence | forged session, removed role, wildcard authority, read-as-delete, self-approval, stale claim/fence, cost overrun |
| G4 Concurrency | simultaneous claim/acquire/consume tests | double worker, duplicate grant use, lost update |
| G5 Recovery | faults before effect, after effect/before checkpoint, after checkpoint; terminal sealing and reconcile-only receipt path | duplicate/post-delivery effect, lost receipt, blind retry, poison starvation |
| G6 Evidence/runtime | typed provenance and fresh observation tests | fake provider smoke, cross-task artifact, stale/doc probe |
| G7 Context/memory | selection trace, TTL, classification, provenance and promotion | secret injection, expired rule, changed evidence, direct active jump |
| G8 Integration/release | queue transition and authoritative delivery tests | terminal seed, merge-as-runtime, missing evaluator/freshness |
| G9 Improvement | protected surfaces, held-in/out isolation, safety failures, approvals | test leakage, evaluator gaming, authority self-mutation |

All applicable gates must pass in a clean process. No test may be converted to
an expected failure to hide a production defect.

## Current Automated Coverage

The suite covers:

- trust-on-first-use bootstrap closure, role vocabulary, derived-secret storage,
  session forgery/expiry/revocation, credential rotation, principal disablement,
  and last-owner protection;
- event/state/idempotency/causation/tamper/reopen behavior;
- lease acquisition, renewal, expiry, takeover and stale fencing;
- exact approvals/grants, concurrency, budgets, revocation and memory/rule
  capability separation, closed action vocabulary, lifecycle gates and live
  worker task-claim revalidation;
- outbox crash windows, fake-provider exactly-once, failed effects and negative
  retention, recovery continuation after denial, role removal, expired claims,
  and terminal-effect sealing;
- authenticated artifact/evidence provenance, typed producer roles, and
  independent evaluator requirements;
- missing, stale, unhealthy, identity-mismatched, contradictory and
  documentation-based observations;
- segment-safe scope and encoded traversal rejection;
- Integration Queue illegal transitions and caller-forged delivery guards;
- context selection/rejection and token budget;
- memory provenance/TTL/held-out/exact approval;
- improvement protected surfaces, held-in/out isolation, safety failures and
  separate limited/active approvals, canonical promotion-record authority
  readback, and projection/event tamper matrices;
- same-snapshot replay/repair with scheduler operational consistency checks and
  refusal to guess missing projections after execution history.

Remaining release work includes secondary-ledger replay coverage, POSIX-shell
installer execution, real-adapter conformance, and the 24/72-hour soak runs.

## Chaos Matrix

For each idempotent adapter run:

1. crash before capability consumption;
2. crash after grant consumption but before effect;
3. crash after external effect but before receipt checkpoint;
4. crash during checkpoint transaction;
5. crash after checkpoint but before worker acknowledgement;
6. duplicate recovery workers;
7. stale worker resumes after lease takeover;
8. provider returns success, failure, unknown, timeout, and conflicting receipt;
9. database is reopened in a fresh process;
10. projection is corrupted while the canonical event chain remains valid.

Assertions: no unauthorized side effect, no duplicate idempotent effect, no
lost negative result, stable receipt digest, current fence only, bounded retry,
and deterministic replay.

## Long-Running Soak

Use synthetic adapters and no paid provider:

- 24-hour baseline, then 72-hour release candidate;
- multiple local worker processes claiming a mixed queue;
- randomized worker termination and restart;
- lease TTL shorter than some simulated task durations with heartbeat renewal;
- retryable and non-retryable failure mix;
- context and observation expiry during runs;
- periodic backup/restore into a new directory;
- event/projection verification after every fault batch.

Track:

- duplicate effect count (target 0 for conforming idempotent adapter);
- unauthorized effect count (target 0);
- unreconciled outbox age and count;
- stale lease rejection count;
- retry/circuit-open distribution;
- time to recovery after process death;
- event/projection mismatch count;
- evidence overclaim attempts rejected;
- context selected/rejected tokens and expired instruction count;
- held-out safety failures and promotion rejection rate.

## Discovery, Promotion Validation and Sealed Test

- Discovery/`held_in` may expose traces, failures and examples to the proposer.
- Promotion-validation/`held_out` is controlled by an independent evaluator.
  Because every accept/reject leaks information, repeated use makes it adaptive
  validation. Limit query count and rotate it.
- `sealed` is never used for proposal search or limited promotion. Run it only
  after the limited candidate is frozen and before active promotion.
- Discovery, promotion-validation and sealed dataset digests must all differ.
- Candidate code/prompts cannot read validation or sealed examples/answers.
- Evaluator version and dataset digest are immutable inputs to the eval record.
- Any safety failure rejects the candidate even when aggregate metrics pass.
- Promotion approval binds proposal, candidate digest, target state, and must
  occur after the applicable evaluation.
- Limited and active promotion require separate decisions. Active promotion
  additionally requires a clean sealed evaluation.
- If a sealed result causes a new edit, mark that set burned; it is now
  validation and a fresh sealed set is required.

## Real Adapter Conformance

A new adapter cannot inherit the fake-provider result. It must independently
demonstrate:

- native idempotency key or deterministic reconciliation;
- request/receipt digest and target identity;
- safe unknown-result handling;
- rate/cost limits and integer minor-unit accounting where money is involved;
- secret isolation and redaction;
- retry classification and circuit breaker;
- fresh target/runtime observation;
- provider smoke under explicit cost authority;
- negative-path evidence and rollback.

## Claim Matrix

| Test result | Maximum supported claim |
|---|---|
| Static parser/schema/unit tests | structure verification |
| Local kernel + fake adapter + crash/replay | local runtime verification |
| Explicit real-provider gated smoke | provider smoke for that adapter/path only |
| Target user/owner acceptance record | human acceptance for the reviewed result |
| Customer/market/ROI evidence | business validation for that hypothesis |
| Provenance + held-out + exact memory approval | durable memory promotion |
| Promotion-validation + clean sealed test + exact separate rule approval | active-rule promotion |

Every report must include non-claims and the exact environment/dataset/adapter
identity.
