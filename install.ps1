<#
.SYNOPSIS
    Installs the DirectoryServicesToolkit module from the latest GitHub release.

.DESCRIPTION
    Downloads the latest release zip from GitHub, extracts DirectoryServicesToolkit.psm1
    and DirectoryServicesToolkit.psd1, and places them in a versioned subfolder under the
    current user's PowerShell module path.

    Supports PowerShell 7+ (PSModulePath: Documents/PowerShell/Modules) and
    Windows PowerShell 5.1 (Documents/WindowsPowerShell/Modules).

.EXAMPLE
    irm https://raw.githubusercontent.com/jschell/DirectoryServicesToolkit/main/install.ps1 | iex

.NOTES
    Requires internet access to api.github.com and objects.githubusercontent.com.
    Run as the user who will import the module — no elevation required.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoOwner  = 'jschell'
$RepoName   = 'DirectoryServicesToolkit'
$ModuleName = 'DirectoryServicesToolkit'

# ── Resolve install path ──────────────────────────────────────────────────────

function Get-UserModulePath
{
    # Prefer the first writable path in PSModulePath that sits under the user profile
    $userProfile = [Environment]::GetFolderPath('UserProfile')
    $modulePaths  = $env:PSModulePath -split [IO.Path]::PathSeparator

    $candidate = $modulePaths | Where-Object { $_ -like "$userProfile*" } | Select-Object -First 1

    if (-not $candidate)
    {
        # Fallback: use the Documents-based path for the running PS edition
        $docs = [Environment]::GetFolderPath('MyDocuments')
        $candidate = if ($PSVersionTable.PSEdition -eq 'Core')
        {
            Join-Path $docs 'PowerShell\Modules'
        }
        else
        {
            Join-Path $docs 'WindowsPowerShell\Modules'
        }
    }

    $candidate
}

# ── Fetch latest release metadata ─────────────────────────────────────────────

Write-Host "Querying latest release from GitHub..." -ForegroundColor Cyan

$apiUrl  = "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
$headers = @{ 'User-Agent' = 'DirectoryServicesToolkit-Installer' }

$release = Invoke-RestMethod -Uri $apiUrl -Headers $headers
$version = $release.tag_name -replace '^v', ''
$zipUrl  = $release.assets |
               Where-Object { $_.name -like '*.zip' } |
               Select-Object -ExpandProperty browser_download_url -First 1

if (-not $zipUrl)
{
    throw "No zip asset found in release $($release.tag_name). Ensure the release workflow has run successfully."
}

Write-Host "Found release: v$version" -ForegroundColor Cyan

# ── Download ──────────────────────────────────────────────────────────────────

$tmpZip     = Join-Path ([IO.Path]::GetTempPath()) "$ModuleName-$version.zip"
$tmpExtract = Join-Path ([IO.Path]::GetTempPath()) "$ModuleName-$version"

Write-Host "Downloading $zipUrl ..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $zipUrl -OutFile $tmpZip -UseBasicParsing

# ── Extract ───────────────────────────────────────────────────────────────────

if (Test-Path $tmpExtract) { Remove-Item $tmpExtract -Recurse -Force }
Expand-Archive -Path $tmpZip -DestinationPath $tmpExtract -Force

# ── Install ───────────────────────────────────────────────────────────────────

$modulePath    = Get-UserModulePath
$installFolder = Join-Path $modulePath "$ModuleName\$version"

$null = New-Item -ItemType Directory -Path $installFolder -Force

$filesToInstall = @(
    "$ModuleName.psm1"
    "$ModuleName.psd1"
)

foreach ($file in $filesToInstall)
{
    $src = Get-ChildItem -Path $tmpExtract -Filter $file -Recurse | Select-Object -First 1
    if (-not $src)
    {
        throw "Expected file '$file' not found in the release archive."
    }
    Copy-Item -Path $src.FullName -Destination $installFolder -Force
}

# Clean up temp files
Remove-Item $tmpZip     -Force -ErrorAction SilentlyContinue
Remove-Item $tmpExtract -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Installed $ModuleName v$version to:" -ForegroundColor Green
Write-Host "  $installFolder" -ForegroundColor Green
Write-Host ""
Write-Host "Import with:" -ForegroundColor Yellow
Write-Host "  Import-Module $ModuleName" -ForegroundColor Yellow
