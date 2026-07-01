param(
    [string]$OutputRoot = "dist_offline",
    [string]$PackageName = "GEM300_Log_Analyzer_Offline",
    [string]$PythonCommand = "",
    [string]$PythonVersion = "3.14"
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$PackageRoot = Join-Path $RepoRoot $OutputRoot
$TargetRoot = Join-Path $PackageRoot $PackageName
$AppRoot = Join-Path $TargetRoot "app"
$WheelsRoot = Join-Path $TargetRoot "wheels"

if (Test-Path $TargetRoot) {
    Remove-Item -LiteralPath $TargetRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $AppRoot, $WheelsRoot | Out-Null

$excludeDirs = @(".git", ".venv", "dist", "dist_offline", "build", "__pycache__", ".pytest_cache")
$excludeFiles = @(".DS_Store", "*.pyc", "*.pyo")

Get-ChildItem -LiteralPath $RepoRoot -Force | Where-Object {
    $excludeDirs -notcontains $_.Name -and
    $_.Name -ne $OutputRoot -and
    $_.Name -ne $PackageName
} | ForEach-Object {
    $destination = Join-Path $AppRoot $_.Name
    if ($_.PSIsContainer) {
        Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse -Force -Exclude $excludeFiles
    }
    else {
        if ($_.Name -notlike ".DS_Store") {
            Copy-Item -LiteralPath $_.FullName -Destination $destination -Force
        }
    }
}

function Resolve-PipPythonCommand {
    if ($PythonCommand) {
        return $PythonCommand
    }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return "py"
    }
    return "python"
}

$PipPython = Resolve-PipPythonCommand
$Requirements = Join-Path $RepoRoot "src\requirements.txt"
$AbiTag = "cp" + $PythonVersion.Replace(".", "")
Write-Host "Downloading Windows x64 wheels for Python $PythonVersion ($AbiTag)..."
& $PipPython -m pip download `
    -r $Requirements `
    -d $WheelsRoot `
    --platform win_amd64 `
    --implementation cp `
    --python-version $PythonVersion `
    --abi $AbiTag `
    --only-binary=:all:
if ($LASTEXITCODE -ne 0) {
    throw "pip download failed for Python $PythonVersion ($AbiTag)."
}

Copy-Item -LiteralPath (Join-Path $RepoRoot "src\tools\install_offline.ps1") -Destination (Join-Path $TargetRoot "install_offline.ps1") -Force
Copy-Item -LiteralPath (Join-Path $RepoRoot "src\tools\README_OFFLINE_INSTALL.md") -Destination (Join-Path $TargetRoot "README_INSTALL.md") -Force

Write-Host "Offline package created: $TargetRoot"
Write-Host "Python installer and ODBC driver installer are intentionally NOT included."


