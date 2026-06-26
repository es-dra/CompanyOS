param(
    [string]$InstallRoot = "$HOME\.company-os\CompanyOS",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$sourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$companyHome = Split-Path -Parent $InstallRoot

if ((Test-Path -LiteralPath $InstallRoot) -and -not $Force) {
    throw "Install root already exists: $InstallRoot. Re-run with -Force to replace runtime kit files."
}

New-Item -ItemType Directory -Force -Path $companyHome | Out-Null
New-Item -ItemType Directory -Force -Path "$companyHome\runs", "$companyHome\feedback-outbox", "$companyHome\projects" | Out-Null

if (Test-Path -LiteralPath $InstallRoot) {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null

$items = @("AGENTS.md", "LICENSE", "README.md", "VERSION", "bin", "core", "gfr", "runtime", "templates", "adapters", "privacy", "examples")
foreach ($item in $items) {
    Copy-Item -LiteralPath (Join-Path $sourceRoot $item) -Destination $InstallRoot -Recurse -Force
}

@"
COMPANY_OS_HOME=$companyHome
COMPANY_OS_REPO=$InstallRoot
"@ | Set-Content -LiteralPath (Join-Path $companyHome "company-os.env") -Encoding UTF8

Write-Host "Installed CompanyOS to $InstallRoot"
Write-Host "Runtime home: $companyHome"
