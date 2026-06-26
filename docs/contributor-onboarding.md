# Contributor Onboarding

This guide explains how a developer or agent should start contributing to a
project that uses CompanyOS.

## First-Time Setup

Clone once:

```powershell
git clone https://github.com/es-dra/CompanyOS.git
cd CompanyOS
.\install.ps1
.\bin\company-os.ps1 validate
```

For later updates, do not clone again. Use:

```powershell
git fetch origin
git pull --ff-only
```

## Working On A Project

Each project should keep its own repository and its own local instructions.

Recommended flow:

```text
read project AGENTS.md
  -> read CompanyOS adapter guidance
  -> classify task with GFR startup contract
  -> create a branch
  -> implement
  -> verify
  -> open PR or handoff
```

Use a feature branch:

```powershell
git checkout -b feature/short-task-name origin/main
```

or, if the project uses `master`:

```powershell
git checkout -b feature/short-task-name origin/master
```

## Collaborator Model

Shared development should use GitHub collaboration, not shared local folders.

- Maintainer invites contributors in GitHub.
- Contributors clone the repository once.
- Contributors work on branches.
- Changes land through PRs or maintainer-reviewed merges.
- Local `.env`, provider config, private media, and secrets stay local.

## Before Opening A PR

Run the project-specific verification commands, plus any CompanyOS validation
when CompanyOS files changed:

```powershell
.\bin\company-os.ps1 validate
git diff --check
```

Do not claim human acceptance, business validation, or durable rule promotion
from tests alone.

## AFS Example

For AgentFlow Studio, new contributors should start from:

```text
AGENTS.md
docs/company_operating_model.md
docs/GFR_EXECUTION_PROJECTION.md
TASK_TRACKER.md
docs/CONTRIBUTOR_ONBOARDING.md
```

AFS contributors should not copy private Company OS source material, provider
secrets, raw provider responses, signed URLs, generated media bytes, customer
material, or real costs into the AFS repository.

