# GFR Startup and Compilation Contract

GFR is the compiler boundary inside CompanyOS. It turns owner intent and
human-readable authoring packets into strict `GoalSpec` and `TaskSpec` runtime
objects. Templates, project books, ledgers, and thread prompts are compiler
inputs; they are not direct automation authority.

## Authoring Intake

Collect only fields that change execution:

- target outcome and explicit non-goals;
- success evidence level and independent evaluator requirement;
- read, write, and forbidden scopes;
- capability gates, budgets, use limits, and human decisions;
- runtime surfaces whose state can drift;
- task objective, expected delta, primary surface, workflow steps, retry limit;
- integration, deletion/retirement, improvement, and close routes.

Program Mode also records branch/upstream/dirty state, base/stack shape, remote
heads, PR path, relevant ports/processes, provider/tool gates, and worker
write/close boundaries. These facts do not become capabilities by being listed.

## Compilation

```text
authoring Goal Contract
  -> normalize and classify authority
  -> reject ambiguous/open gates without exact capability
  -> compile strict GoalSpec

authoring Task Packet + GoalSpec
  -> map authoring field names
  -> verify goal identity
  -> prove capability/scope/runtime-surface subset
  -> compile strict TaskSpec
```

The reference compiler is available as:

```powershell
python -m companyos_runtime compile-goal --input goal-authoring.json
python -m companyos_runtime compile-task --input task-authoring.json --goal-spec compiled-goal.json
```

It reports authoring fields that remain contextual rather than executable.
Unknown fields in compiled specs are rejected.

## Runtime Handoff

The compiled packet must contain:

- stable goal/task identifiers;
- target outcome, objective, and expected delta;
- exact evidence target and evaluator flag;
- read/write/forbidden scope;
- bounded capability list;
- required runtime surfaces;
- integration requirement;
- workflow step identifiers and maximum attempts;
- idempotency route and stop/circuit-breaker policy at the control boundary.

Execution then follows:

```text
compile before execution
scope before write
lease before concurrent mutation
exact grant before side effect
evidence before claim
fresh observation before runtime claim
integration before delivery
held-out evaluation before promotion
```

When local, remote, server, process, port, or provider state can drift, compile
a Runtime Surface Vector and record a fresh probe. Documentation is not a
runtime probe.

Reusable friction enters the Improvement Queue as a candidate. It cannot
directly mutate authority order, capability policy, event integrity, held-out
data, evaluator code, security policy, memory, or active rules.
