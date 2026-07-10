param(
    [string]$InstallRoot = "$HOME\.company-os\CompanyOS",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::Equals($fullPath, $root, [StringComparison]::OrdinalIgnoreCase)) {
        return $root
    }
    return $fullPath.TrimEnd([char[]]"\/")
}

function Test-DescendantPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )

    $parentPrefix = (Get-NormalizedPath $Parent) + [IO.Path]::DirectorySeparatorChar
    $normalizedChild = Get-NormalizedPath $Child
    return $normalizedChild.StartsWith(
        $parentPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Assert-DescendantPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not (Test-DescendantPath -Parent $Parent -Child $Child)) {
        throw "$Label escaped canonical CompanyOS home: $Child"
    }
}

function Assert-NoReparsePoint {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $cursor = Get-NormalizedPath $Path
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label contains a reparse point: $cursor"
            }
        }
        $parent = Split-Path -Parent $cursor
        if (-not $parent -or [string]::Equals(
                $parent,
                $cursor,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            break
        }
        $cursor = $parent
    }
}

$sourceRoot = Get-NormalizedPath (Split-Path -Parent $MyInvocation.MyCommand.Path)
$installPath = Get-NormalizedPath $InstallRoot
$companyHome = Get-NormalizedPath (Split-Path -Parent $installPath)
$homePath = Get-NormalizedPath $HOME
$driveRoot = [IO.Path]::GetPathRoot($installPath)
$markerName = ".companyos-runtime-install"
$markerPath = Join-Path $installPath $markerName

if ($installPath -in @($sourceRoot, $companyHome, $homePath, $driveRoot)) {
    throw "Unsafe install root: $installPath"
}
if ($companyHome -in @($homePath, $driveRoot)) {
    throw "Unsafe CompanyOS home: $companyHome"
}
Assert-DescendantPath -Parent $companyHome -Child $installPath -Label "Install path"
Assert-NoReparsePoint -Path $companyHome -Label "CompanyOS home"
Assert-NoReparsePoint -Path $installPath -Label "Install path"

if (Test-Path -LiteralPath $installPath) {
    if (-not $Force) {
        throw "Install root already exists: $installPath. Re-run with -Force only for a marked CompanyOS installation."
    }
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        throw "Refusing recursive replacement of an unmarked directory: $installPath"
    }
    Assert-NoReparsePoint -Path $markerPath -Label "Install marker"
}

New-Item -ItemType Directory -Force -Path $companyHome | Out-Null
New-Item -ItemType Directory -Force -Path (
    (Join-Path $companyHome "state"),
    (Join-Path $companyHome "runs"),
    (Join-Path $companyHome "feedback-outbox"),
    (Join-Path $companyHome "projects"),
    (Join-Path $companyHome "demos")
) | Out-Null
Assert-NoReparsePoint -Path $companyHome -Label "CompanyOS home"
foreach ($managedDirectory in @("state", "runs", "feedback-outbox", "projects", "demos")) {
    $managedPath = Join-Path $companyHome $managedDirectory
    Assert-DescendantPath -Parent $companyHome -Child $managedPath -Label "Managed directory"
    Assert-NoReparsePoint -Path $managedPath -Label "Managed directory"
}

$staging = Get-NormalizedPath "$installPath.staging-$([guid]::NewGuid().ToString('N'))"
Assert-DescendantPath -Parent $companyHome -Child $staging -Label "Staging path"
Assert-NoReparsePoint -Path $staging -Label "Staging path"
New-Item -ItemType Directory -Path $staging | Out-Null
try {
    Assert-NoReparsePoint -Path $staging -Label "Staging path"
    $items = @(
        "AGENTS.md", "LICENSE", "README.md", "VERSION", "pyproject.toml",
        "companyos_runtime", "bin", "core", "full-stack", "gfr", "runtime",
        "templates", "adapters", "privacy", "examples", "docs"
    )
    foreach ($item in $items) {
        Copy-Item -LiteralPath (Join-Path $sourceRoot $item) -Destination $staging -Recurse -Force
    }
    "CompanyOS Runtime Kit managed installation" |
        Set-Content -LiteralPath (Join-Path $staging $markerName) -Encoding UTF8

    if (Test-Path -LiteralPath $installPath) {
        Assert-NoReparsePoint -Path $installPath -Label "Install path"
        $resolvedInstall = Get-NormalizedPath (Resolve-Path -LiteralPath $installPath).Path
        if (-not [string]::Equals(
                $resolvedInstall,
                $installPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Resolved install path changed unexpectedly: $resolvedInstall"
        }
        Assert-DescendantPath -Parent $companyHome -Child $resolvedInstall -Label "Install path"
        Remove-Item -LiteralPath $resolvedInstall -Recurse -Force
    }
    Assert-NoReparsePoint -Path $companyHome -Label "CompanyOS home"
    Assert-NoReparsePoint -Path $staging -Label "Staging path"
    Assert-DescendantPath -Parent $companyHome -Child $installPath -Label "Install path"
    Move-Item -LiteralPath $staging -Destination $installPath
    Assert-NoReparsePoint -Path $installPath -Label "Installed path"
}
finally {
    if (Test-Path -LiteralPath $staging) {
        try {
            Assert-NoReparsePoint -Path $staging -Label "Staging cleanup path"
            Assert-DescendantPath -Parent $companyHome -Child $staging -Label "Staging cleanup path"
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
        catch {
            Write-Warning "Unsafe staging cleanup was refused: $($_.Exception.Message)"
        }
    }
}

$environmentPath = Join-Path $companyHome "company-os.env"
Assert-NoReparsePoint -Path $companyHome -Label "CompanyOS home"
Assert-DescendantPath -Parent $companyHome -Child $environmentPath -Label "Environment file"
Assert-NoReparsePoint -Path $environmentPath -Label "Environment file"
@"
COMPANY_OS_HOME=$companyHome
COMPANY_OS_REPO=$installPath
COMPANY_OS_DB=$(Join-Path $companyHome "state\runtime.db")
"@ | Set-Content -LiteralPath $environmentPath -Encoding UTF8

Write-Host "Installed CompanyOS to $installPath"
Write-Host "Runtime home: $companyHome"
Write-Host "Initialize with: & `"$(Join-Path $installPath 'bin\company-os.ps1')`" runtime-init -Database `"$(Join-Path $companyHome 'state\runtime.db')`""
