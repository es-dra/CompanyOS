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
- Keep files small, direct, and installable. Avoid parallel drafts and duplicate
  naming.

## Startup

For substantial work:

1. Read `README.md`.
2. Read `core/authority-order.md`.
3. Read `core/evidence-states.md`.
4. Read `full-stack/engineering-standard.md` for software work.
5. Read `gfr/startup-contract.md`.
6. Read `templates/PROJECT_COMPANYOS_ADOPTION.md` for project adoption changes.
7. Read `templates/PROJECTION_DECISION.md` for source-to-public projection changes.
8. Read `docs/source-sync.md` for distribution, projection, or feedback changes.
9. Read `docs/contributor-onboarding.md` for collaborator onboarding changes.
10. Define the write scope and verification command before editing.

## Verification

Before claiming a change is ready:

```powershell
.\bin\company-os.ps1 validate
git diff --check
```

If a task produces reusable operational evidence, create a taskrun log:

```powershell
.\bin\company-os.ps1 new-taskrun -Project CompanyOS -Summary "<summary>" -EvidenceState structure_verification
```

If a task projects private source guidance into CompanyOS, create a projection
decision draft and keep candidate material bounded:

```powershell
.\bin\company-os.ps1 new-projection -SourceObject "<source>" -SourceStatus candidate -SourceLayer feedback_promotion -ProjectionTarget "<target>" -ProjectedAs feedback_export_shape -CandidatePublicBoundary feedback_shape_only -Decision defer
```
