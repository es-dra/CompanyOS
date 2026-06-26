# Project CompanyOS Adoption

Use this template when a project opts into CompanyOS.

## Project

- Repository:
- Default branch:
- Main product surface:
- Runtime / backend boundary:
- Frontend entry:

## Required Reading

- Project `AGENTS.md`:
- Project README:
- Task tracker:
- Architecture docs:
- CompanyOS adapter:

## Local Setup

```powershell
git clone <project-url>
cd <project>
git fetch origin
```

Project-specific install:

```powershell
# fill in project commands
```

## Branch Rule

Do not work directly on the main branch.

```powershell
git checkout -b feature/<short-task-name> origin/<default-branch>
```

## CompanyOS Boundary

This project may use:

- CompanyOS authority order;
- GFR startup contract;
- full-stack engineering standard;
- evidence states;
- taskrun logs;
- feedback packet templates.

This project must not store:

- private Company OS source material;
- secrets or provider keys;
- signed URLs;
- raw provider responses;
- customer material;
- real costs;
- generated media bytes unless explicitly allowed by project policy.

## Verification

Project verification:

```powershell
# fill in project commands
```

CompanyOS verification, when CompanyOS files changed:

```powershell
.\bin\company-os.ps1 validate
git diff --check
```

## Feedback Route

- Project-local handoff path:
- CompanyOS feedback candidate path:
- Maintainer review owner:

