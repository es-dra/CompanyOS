param(
    [Parameter(Position = 0)]
    [ValidateSet("validate", "new-taskrun", "new-feedback", "new-projection")]
    [string]$Command = "validate",

    [string]$Project = "unknown",
    [string]$Summary = "",
    [string]$TaskClass = "general",
    [string]$SourceObject = "",
    [ValidateSet("active", "active_positioning", "limited", "candidate", "draft", "historical_draft", "template", "retired")]
    [string]$SourceStatus = "candidate",
    [ValidateSet("doctrine", "control_plane", "project_capsule", "method", "evidence", "feedback_promotion", "distribution_projection", "external_signal_intake", "unknown")]
    [string]$SourceLayer = "unknown",
    [string]$ProjectionTarget = "",
    [ValidateSet(
        "public_rule",
        "public_positioning",
        "bounded_guidance",
        "runtime_contract",
        "schema",
        "template",
        "adapter_guidance",
        "redaction_policy",
        "validation_command",
        "sanitized_example",
        "project_adoption_packet",
        "feedback_export_shape",
        "draft_template",
        "schema_under_review",
        "migration_note",
        "public_safe_method_summary"
    )]
    [string]$ProjectedAs = "template",
    [ValidateSet("not_candidate", "template_only", "feedback_shape_only", "schema_under_review_only", "sanitized_example_only", "blocked")]
    [string]$CandidatePublicBoundary = "template_only",
    [switch]$PublicSafe,
    [ValidateSet("redacted", "requires_review", "blocked")]
    [string]$RedactionStatus = "requires_review",
    [ValidateSet("project", "defer", "block")]
    [string]$Decision = "defer",
    [ValidateSet(
        "rule_friction",
        "workflow_gap",
        "tooling_gap",
        "evidence_gap",
        "context_gap",
        "projection_gap",
        "successful_pattern"
    )]
    [string]$Kind = "workflow_gap",
    [ValidateSet(
        "candidate_rule",
        "project_handoff",
        "tooling_issue",
        "discard",
        "owner_review"
    )]
    [string]$RecommendedRoute = "owner_review",
    [ValidateSet(
        "structure_verification",
        "runtime_verification",
        "provider_smoke",
        "human_acceptance",
        "business_validation",
        "durable_rule_promotion",
        "not_verified"
    )]
    [string]$EvidenceState = "not_verified",
    [string]$CompanyHome = "$HOME\.company-os"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

function Test-JsonFile {
    param([string]$Path)
    Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json | Out-Null
}

function Test-RequiredProperties {
    param(
        [object]$Object,
        [string[]]$Required,
        [string]$Label
    )

    foreach ($name in $Required) {
        if (-not ($Object.PSObject.Properties.Name -contains $name)) {
            throw "$Label missing required property: $name"
        }
    }
}

function Test-ProjectionDecisionRecord {
    param(
        [object]$Record,
        [string]$Label
    )

    Test-RequiredProperties -Object $Record -Required @(
        "decision_id",
        "created_at",
        "source_object",
        "source_status",
        "source_layer",
        "projection_target",
        "projected_as",
        "public_safe",
        "redaction_status",
        "candidate_public_boundary",
        "private_material_risk",
        "misleading_identity_risk",
        "release_boundary",
        "decision",
        "validation",
        "owner_review"
    ) -Label $Label

    if ($Record.source_status -eq "candidate") {
        $blocked = @("public_rule", "public_positioning", "runtime_contract")
        if ($blocked -contains $Record.projected_as) {
            throw "$Label projects candidate material as $($Record.projected_as). Candidate material must stay template, schema-under-review, feedback-shape, or sanitized-example only."
        }
        if ($Record.candidate_public_boundary -eq "not_candidate") {
            throw "$Label has source_status candidate but candidate_public_boundary is not_candidate."
        }
    }

    if ($Record.public_safe -and $Record.redaction_status -ne "redacted") {
        throw "$Label is public_safe but redaction_status is not redacted."
    }

    if (-not $Record.release_boundary -or $Record.release_boundary.Count -eq 0) {
        throw "$Label must include at least one release_boundary item."
    }
}

function Invoke-Validate {
    $required = @(
        "README.md",
        "AGENTS.md",
        "core\authority-order.md",
        "core\evidence-states.md",
        "full-stack\engineering-standard.md",
        "full-stack\api-contract.md",
        "full-stack\frontend-boundary.md",
        "full-stack\release-checklist.md",
        "gfr\startup-contract.md",
        "runtime\taskrun-log.schema.json",
        "runtime\feedback-export.schema.json",
        "runtime\project-adoption.schema.json",
        "runtime\projection-decision.schema.json",
        "templates\TASK_STARTUP_PACKET.md",
        "templates\FEEDBACK_PACKET.md",
        "templates\PROJECT_COMPANYOS_ADOPTION.md",
        "templates\PROJECTION_DECISION.md",
        "privacy\redaction-policy.md",
        "adapters\codex\AGENTS.md",
        "docs\source-sync.md",
        "docs\contributor-onboarding.md"
    )

    foreach ($item in $required) {
        $path = Join-Path $RepoRoot $item
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Missing required file: $item"
        }
    }

    Get-ChildItem -LiteralPath (Join-Path $RepoRoot "runtime") -Filter *.json -File |
        ForEach-Object { Test-JsonFile $_.FullName }

    Get-ChildItem -LiteralPath (Join-Path $RepoRoot "examples") -Filter *.json -File |
        ForEach-Object { Test-JsonFile $_.FullName }

    $projectionExample = Join-Path $RepoRoot "examples\projection-decision.example.json"
    $projectionRecord = Get-Content -Raw -LiteralPath $projectionExample | ConvertFrom-Json
    Test-ProjectionDecisionRecord -Record $projectionRecord -Label "examples/projection-decision.example.json"

    $feedbackSchemaText = Get-Content -Raw -LiteralPath (Join-Path $RepoRoot "runtime\feedback-export.schema.json")
    $legacyFeedbackFieldPattern = ("external" + "_mechanism|adoption" + "_state|thought" + "_candidate")
    if ($feedbackSchemaText -match $legacyFeedbackFieldPattern) {
        throw "feedback-export.schema.json exposes private external-signal intake fields."
    }

    Write-Host "CompanyOS validation passed."
}

function New-Taskrun {
    if ([string]::IsNullOrWhiteSpace($Summary)) {
        throw "Summary is required for new-taskrun."
    }

    $runsDir = Join-Path $CompanyHome "runs"
    New-Item -ItemType Directory -Force -Path $runsDir | Out-Null

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $safeProject = ($Project -replace "[^A-Za-z0-9_.-]", "-").Trim("-")
    if ([string]::IsNullOrWhiteSpace($safeProject)) {
        $safeProject = "unknown"
    }

    $record = [ordered]@{
        taskrun_id = "$timestamp-$safeProject"
        started_at = (Get-Date).ToString("o")
        runtime_kit_version = (Get-Content -Raw -LiteralPath (Join-Path $RepoRoot "VERSION")).Trim()
        project = $Project
        task_summary = $Summary
        task_class = $TaskClass
        context_pack = @(
            "core/authority-order.md",
            "core/evidence-states.md",
            "gfr/startup-contract.md"
        )
        read_scope = @()
        write_scope = @()
        gates = [ordered]@{
            network = "project scoped"
            provider = "closed unless task explicitly opens it"
            external_download = "closed unless task explicitly opens it"
            destructive_operations = "closed unless task explicitly authorizes it"
        }
        evidence_state = $EvidenceState
        verification = @()
        non_claims = @(
            "This log is local operational evidence, not human acceptance or business validation."
        )
        feedback_candidate = $false
        feedback_route = "not decided"
    }

    $outFile = Join-Path $runsDir "$timestamp-$safeProject.taskrun.json"
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $outFile -Encoding UTF8
    Write-Host "Wrote taskrun log: $outFile"
}

function New-Feedback {
    if ([string]::IsNullOrWhiteSpace($Summary)) {
        throw "Summary is required for new-feedback."
    }

    $outboxDir = Join-Path $CompanyHome "feedback-outbox"
    New-Item -ItemType Directory -Force -Path $outboxDir | Out-Null

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $machineLabel = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "local-machine" }

    $record = [ordered]@{
        export_id = "$timestamp-feedback"
        created_at = (Get-Date).ToString("o")
        runtime_kit_version = (Get-Content -Raw -LiteralPath (Join-Path $RepoRoot "VERSION")).Trim()
        source_machine_label = $machineLabel
        redaction_status = "requires_review"
        items = @(
            [ordered]@{
                item_id = "$timestamp-item"
                kind = $Kind
                summary = $Summary
                source_scope = "local operator summary"
                evidence_refs = @()
                recommended_route = $RecommendedRoute
            }
        )
    }

    $outFile = Join-Path $outboxDir "$timestamp.feedback-export.json"
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $outFile -Encoding UTF8
    Write-Host "Wrote feedback export draft: $outFile"
}

function New-Projection {
    if ([string]::IsNullOrWhiteSpace($SourceObject)) {
        throw "SourceObject is required for new-projection."
    }
    if ([string]::IsNullOrWhiteSpace($ProjectionTarget)) {
        throw "ProjectionTarget is required for new-projection."
    }

    if ($SourceStatus -eq "candidate") {
        $blocked = @("public_rule", "public_positioning", "runtime_contract")
        if ($blocked -contains $ProjectedAs) {
            throw "Candidate source material cannot be projected as $ProjectedAs."
        }
        if ($CandidatePublicBoundary -eq "not_candidate") {
            throw "Candidate source material requires a candidate public boundary."
        }
    }

    $outboxDir = Join-Path $CompanyHome "projection-decisions"
    New-Item -ItemType Directory -Force -Path $outboxDir | Out-Null

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $safeObject = ($SourceObject -replace "[^A-Za-z0-9_.-]", "-").Trim("-")
    if ([string]::IsNullOrWhiteSpace($safeObject)) {
        $safeObject = "source-object"
    }

    $record = [ordered]@{
        decision_id = "$timestamp-projection"
        created_at = (Get-Date).ToString("o")
        source_object = $SourceObject
        source_status = $SourceStatus
        source_layer = $SourceLayer
        source_path = ""
        projection_target = $ProjectionTarget
        projected_as = $ProjectedAs
        public_safe = [bool]$PublicSafe
        redaction_status = $RedactionStatus
        private_material_risk = @()
        candidate_public_boundary = $CandidatePublicBoundary
        misleading_identity_risk = "requires_review"
        release_boundary = @(
            "CompanyOS is a runtime kit, not the full private COS source.",
            "This projection decision does not prove human acceptance, business validation, or durable rule promotion."
        )
        decision = $Decision
        validation = @(
            [ordered]@{
                command = ".\bin\company-os.ps1 validate"
                status = "not_run"
                notes = "Run from the CompanyOS repository before projection is accepted."
            }
        )
        owner_review = "required"
    }

    Test-ProjectionDecisionRecord -Record ([pscustomobject]$record) -Label "new-projection draft"

    $outFile = Join-Path $outboxDir "$timestamp-$safeObject.projection-decision.json"
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $outFile -Encoding UTF8
    Write-Host "Wrote projection decision draft: $outFile"
}

switch ($Command) {
    "validate" { Invoke-Validate }
    "new-taskrun" { New-Taskrun }
    "new-feedback" { New-Feedback }
    "new-projection" { New-Projection }
}
