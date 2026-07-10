# AGENTS.md

CompanyOS is the public-safe runtime projection of a private AI-native Company
OS. Work in this repository must preserve that boundary.

## Operating Rules

- Treat this repository as a runtime kit, not a full private source vault.
- Do not add secrets, customer material, real costs, signed URLs, raw provider
  responses, generated media bytes, or private retrospectives.
- Keep GFR as a compiler module inside CompanyOS; do not make it the repository
  identity.
- Keep Codex as one adapter. The repository must remain understandable by other
  agent runtimes.
- Expose Agentic Operating System authoring objects only as public-safe templates,
  and compile them into strict public-safe runtime contracts:
  AOS Startup Packet, Goal Contract, Task Packet, Evidence Packet, Runtime
  Surface Vector, Integration Queue, and Improvement Queue.
- Keep files small, direct, and installable. Avoid parallel drafts and duplicate
  naming.
- Treat the append-only event ledger and compiled Goal/Task contracts as the
  canonical core. Do not let a template, log, caller boolean, or projection
  overwrite durable facts.
- Keep the SQLite implementation explicitly single-host. Do not claim
  distributed consensus or generic exactly-once delivery.

## Startup

For substantial work:

1. Read `README.md`.
2. Read `core/authority-order.md`.
3. Read `core/evidence-states.md`.
4. Read `full-stack/engineering-standard.md` for software work.
5. Read `gfr/startup-contract.md`.
6. Read `templates/AOS_STARTUP_PACKET.md`, `templates/GOAL_CONTRACT.md`, and
   `templates/TASK_PACKET.md` for AOS runtime-object changes.
7. Read `templates/EVIDENCE_PACKET.md` and
   `templates/RUNTIME_SURFACE_VECTOR.md` for evidence or runtime-state changes.
8. Read `templates/PROJECT_COMPANYOS_ADOPTION.md` for project adoption changes.
9. Read `templates/PROJECTION_DECISION.md` for source-to-public projection changes.
10. Read `docs/source-sync.md` for distribution, projection, or feedback changes.
11. Read `docs/contributor-onboarding.md` for collaborator onboarding changes.
12. Define the write scope and verification command before editing.

## Verification

Before claiming a change is ready:

```powershell
python -B -m unittest discover -s tests -p "test_*.py" -v
.\bin\company-os.ps1 validate
python -m companyos_runtime demo --state-dir "$env:TEMP/companyos-runtime-verification" --fault-at after_effect_before_checkpoint
git diff --check
```

The demo proves local runtime verification only. Delete its dedicated temporary
state after recording the result; do not call it provider smoke.

If a task produces reusable operational evidence, create a run log:

```powershell
.\bin\company-os.ps1 new-run -Project CompanyOS -Summary "<summary>" -EvidenceState structure_verification
```

If a task projects private source guidance into CompanyOS, create a projection
decision draft and keep candidate material bounded:

```powershell
.\bin\company-os.ps1 new-projection -SourceObject "<source>" -SourceStatus candidate -SourceLayer feedback_promotion -ProjectionTarget "<target>" -ProjectedAs feedback_export_shape -CandidatePublicBoundary feedback_shape_only -Decision defer
```
