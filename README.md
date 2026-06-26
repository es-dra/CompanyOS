# CompanyOS

CompanyOS is the public-safe runtime projection of a private AI-native Company
OS.

It gives a developer machine a repeatable operating surface for:

- task startup and context selection;
- full-stack engineering boundaries;
- evidence-state discipline;
- provider and tool gate boundaries;
- local taskrun logging;
- sanitized feedback export;
- adapter-specific agent instructions.

It is not the full private Company OS source vault. It is not a skill library.
GFR is the startup compiler inside CompanyOS. Codex support is one adapter, not
the repository identity.

## Repository Identity

Use:

```text
CompanyOS
Company OS Runtime Kit
```

Do not position this repository as a generic skill collection, an AFS submodule,
or a dump of private strategy material.

## Clone Location

Git places the repository wherever the user runs `git clone`.

Examples:

```powershell
cd D:\Projects
git clone https://github.com/es-dra/CompanyOS.git
```

This creates:

```text
D:\Projects\CompanyOS
```

Codex desktop workspaces can also place the checkout under the workspace path
chosen by the user. The repository itself does not force a clone location.

## Install

PowerShell:

```powershell
.\install.ps1
```

Shell:

```bash
./install.sh
```

Default local layout:

```text
~/.company-os/
  CompanyOS/
  runs/
  feedback-outbox/
  projects/
```

## Task Flow

```text
task request
  -> authority order
  -> GFR startup contract
  -> minimal context pack
  -> execution
  -> verification and evidence boundary
  -> local taskrun log
  -> sanitized feedback export
```

## Contents

```text
core/                 authority order and evidence-state rules
full-stack/           professional software engineering standards
gfr/                  task startup compiler contract
runtime/              taskrun, project adoption, projection decision, and feedback export schemas
templates/            startup, adoption, projection, and feedback templates
adapters/codex/       Codex-facing project instruction adapter
bin/                  lightweight local commands
privacy/              redaction and exclusion policy
examples/             safe example project registration
docs/                 source sync and contributor onboarding guides
```

## Local Commands

Validate the runtime kit files:

```powershell
.\bin\company-os.ps1 validate
```

Read the full-stack standard:

```text
full-stack/engineering-standard.md
```

Create a local taskrun log:

```powershell
.\bin\company-os.ps1 new-taskrun -Project Example -TaskClass "runtime smoke" -Summary "local verification" -EvidenceState structure_verification
```

By default, logs are written to:

```text
~/.company-os/runs/
```

Feedback packet drafts should be written to:

```text
~/.company-os/feedback-outbox/
```

Create a local feedback export draft:

```powershell
.\bin\company-os.ps1 new-feedback -Summary "project startup packet needs clearer read scope" -Kind workflow_gap -RecommendedRoute owner_review
```

Feedback drafts default to `requires_review`; maintainers decide whether they
become project notes, candidate rules, tooling issues, or discarded signals.

Create a local projection decision draft before source-to-runtime projection:

```powershell
.\bin\company-os.ps1 new-projection -SourceObject "Project adoption template" -SourceStatus template -SourceLayer distribution_projection -ProjectionTarget "templates/PROJECT_COMPANYOS_ADOPTION.md" -ProjectedAs template -CandidatePublicBoundary not_candidate -PublicSafe -RedactionStatus redacted -Decision project
```

Projection drafts are written to:

```text
~/.company-os/projection-decisions/
```

Candidate source material must stay bounded as template-only, feedback-shape,
schema-under-review, sanitized-example, or blocked. It must not be projected as
an active CompanyOS rule.

## Source Sync And Onboarding

For the repository/source boundary, read:

```text
docs/source-sync.md
```

For adding new contributors or agent users, read:

```text
docs/contributor-onboarding.md
templates/PROJECT_COMPANYOS_ADOPTION.md
templates/PROJECTION_DECISION.md
```

## Codex Integration Boundary

When Codex opens this repository, root `AGENTS.md` provides the local operating
rules for working on CompanyOS itself.

For another project to use CompanyOS, that project must explicitly reference
the installed runtime kit or include the Codex adapter guidance from:

```text
adapters/codex/AGENTS.md
```

Cloning this repository alone cannot automatically change every Codex project
on a machine. The intended v0.1 behavior is installable local runtime plus
explicit project opt-in.

## Publication Gates

Before publishing a public GitHub repository:

- confirm no private COS source, secrets, customer material, real costs, signed
  URLs, raw provider responses, or generated media bytes are present;
- create the repository from this clean export, not from private source-history;
- tag the first usable release instead of asking users to auto-pull `main`.
