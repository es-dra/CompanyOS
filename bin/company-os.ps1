param(
    [Parameter(Position = 0)]
    [ValidateSet("validate", "new-taskrun")]
    [string]$Command = "validate",

    [string]$Project = "unknown",
    [string]$Summary = "",
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
        "templates\TASK_STARTUP_PACKET.md",
        "templates\FEEDBACK_PACKET.md",
        "templates\PROJECT_COMPANYOS_ADOPTION.md",
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

    Test-JsonFile (Join-Path $RepoRoot "examples\project-registration.example.json")
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
        context_pack = @(
            "core/authority-order.md",
            "core/evidence-states.md",
            "gfr/startup-contract.md"
        )
        evidence_state = $EvidenceState
        verification = @()
        non_claims = @(
            "This log is local operational evidence, not human acceptance or business validation."
        )
        feedback_candidate = $false
    }

    $outFile = Join-Path $runsDir "$timestamp-$safeProject.taskrun.json"
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $outFile -Encoding UTF8
    Write-Host "Wrote taskrun log: $outFile"
}

switch ($Command) {
    "validate" { Invoke-Validate }
    "new-taskrun" { New-Taskrun }
}
