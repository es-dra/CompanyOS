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
If a project opts into CompanyOS, it should keep or reference a project adoption
packet that states required reading, forbidden material, verification commands,
and feedback routes.

Recommended flow:

```text
read project AGENTS.md
  -> read CompanyOS adapter guidance
  -> author and compile GoalSpec / TaskSpec
  -> create a branch
  -> implement
  -> typed evidence and independent evaluation
  -> Integration Queue / runtime freshness
  -> open PR, release route, or handoff
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

Do not claim human acceptance, business validation, durable memory promotion,
or active-rule promotion
from tests alone.

## New Ideas

New operating ideas should arrive as feedback candidates unless a maintainer
has already approved the change. CompanyOS contributors do not need access to
the private source system or its research trail to make a useful public-safe
contribution.
