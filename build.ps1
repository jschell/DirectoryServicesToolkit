#Requires -Module InvokeBuild
<#
.SYNOPSIS
Invoke-Build task file for the DirectoryServicesToolkit module.

.DESCRIPTION
Defines build, test, lint, documentation, and CI pipeline tasks.
Invoke via: Invoke-Build <Task>

Common tasks:
  Invoke-Build Test     - Run all Pester tests
  Invoke-Build Lint     - Run PSScriptAnalyzer
  Invoke-Build LintFix  - Run PSScriptAnalyzer with auto-fix
  Invoke-Build Build    - Concatenate all .ps1 files into a single .psm1, generate .psd1
  Invoke-Build Docs     - Generate platyPS markdown docs
  Invoke-Build CI       - Full pipeline: Lint -> Test -> Build
  Invoke-Build Clean    - Remove build artifacts
#>

$ModuleName          = 'DirectoryServicesToolkit'
$SourcePath          = "$PSScriptRoot/Source"
$SourceManifestPath  = "$SourcePath/$ModuleName.psd1"
$OutputPath          = "$PSScriptRoot/Output"
$TestPath            = "$PSScriptRoot/Tests"
$DocsPath            = "$PSScriptRoot/Docs/en-US"
$ManifestPath        = "$OutputPath/$ModuleName.psd1"
$ModulePath          = "$OutputPath/$ModuleName.psm1"
$AnalyzerSettings    = "$PSScriptRoot/PSScriptAnalyzerSettings.psd1"

# ── Helper ──────────────────────────────────────────────────────────────────

$script:PublicFolderOrder = @(
    'Enumeration'
    'Security'
    'AccountHygiene'
    'Trusts'
    'DomainControllers'
    'DNS'
    'Reporting'
    'Utilities'
)

function Get-PublicFunctions
{
    foreach ($folder in $script:PublicFolderOrder)
    {
        $folderPath = Join-Path $SourcePath $folder
        if (Test-Path $folderPath)
        {
            Get-ChildItem -Path $folderPath -Filter '*.ps1' |
                Sort-Object Name |
                ForEach-Object { $_.BaseName }
        }
    }
}

# ── Tasks ────────────────────────────────────────────────────────────────────

task Clean {
    if (Test-Path $OutputPath)
    {
        Remove-Item $OutputPath -Recurse -Force
        Write-Build Green "Removed $OutputPath"
    }
}

task Build Clean, {
    $null = New-Item -ItemType Directory -Path $OutputPath -Force

    $psm1Content = [System.Text.StringBuilder]::new()

    # Private helpers first — public functions may depend on them
    $privatePath = Join-Path $SourcePath 'Private'
    if (Test-Path $privatePath)
    {
        $null = $psm1Content.AppendLine("# ── Private Helpers $(('─' * 60))")
        Get-ChildItem -Path $privatePath -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
            $null = $psm1Content.AppendLine("")
            $null = $psm1Content.AppendLine((Get-Content $_.FullName -Raw).TrimEnd())
        }
        $null = $psm1Content.AppendLine("")
    }

    # Public functions in folder order matching Source/DirectoryServicesToolkit.psm1
    foreach ($folder in $script:PublicFolderOrder)
    {
        $folderPath = Join-Path $SourcePath $folder
        if (-not (Test-Path $folderPath)) { continue }

        $null = $psm1Content.AppendLine("# ── $folder $(('─' * (60 - $folder.Length)))")
        Get-ChildItem -Path $folderPath -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
            $null = $psm1Content.AppendLine("")
            $null = $psm1Content.AppendLine((Get-Content $_.FullName -Raw).TrimEnd())
        }
        $null = $psm1Content.AppendLine("")
    }

    $psm1Content.ToString() | Set-Content -Path $ModulePath -Encoding UTF8

    # Version is owned by Source/DirectoryServicesToolkit.psd1 — read it from there.
    $sourceManifest = Import-PowerShellDataFile $SourceManifestPath
    $moduleVersion  = $sourceManifest.ModuleVersion.ToString()

    $publicFunctions = Get-PublicFunctions

    # Generate the distributable manifest in Output/
    $manifestParams = @{
        Path              = $ManifestPath
        ModuleVersion     = $moduleVersion
        GUID              = $sourceManifest.GUID
        Author            = $sourceManifest.Author
        Description       = $sourceManifest.Description
        PowerShellVersion = $sourceManifest.PowerShellVersion
        RootModule        = "$ModuleName.psm1"
        FunctionsToExport = $publicFunctions
        Tags              = $sourceManifest.PrivateData.PSData.Tags
        LicenseUri        = $sourceManifest.PrivateData.PSData.LicenseUri
        ProjectUri        = $sourceManifest.PrivateData.PSData.ProjectUri
    }
    New-ModuleManifest @manifestParams

    # Sync FunctionsToExport back to Source/psd1 as functions are added/removed.
    # ModuleVersion is left unchanged — only the release workflow bumps it.
    Update-ModuleManifest -Path $SourceManifestPath -FunctionsToExport $publicFunctions

    Write-Build Green "Built $ModuleName v$moduleVersion -> $OutputPath"
}

task Lint {
    $results = Invoke-ScriptAnalyzer -Path $SourcePath -Recurse -Settings $AnalyzerSettings
    if ($results)
    {
        $results | Format-Table -AutoSize
        throw "PSScriptAnalyzer found $($results.Count) issue(s). Fix before committing."
    }
    else
    {
        Write-Build Green "Lint passed — no issues found"
    }
}

task LintFix {
    Invoke-ScriptAnalyzer -Path $SourcePath -Recurse -Settings $AnalyzerSettings -Fix
    Write-Build Green "Auto-fixable issues resolved"
}

task Test {
    $pesterConfig = New-PesterConfiguration
    $pesterConfig.Run.Path = $TestPath
    $pesterConfig.Run.Exit = $true
    $pesterConfig.Output.Verbosity = 'Detailed'
    $pesterConfig.Filter.Tag = 'Unit'
    $pesterConfig.CodeCoverage.Enabled = $false

    $result = Invoke-Pester -Configuration $pesterConfig
    if ($result.FailedCount -gt 0)
    {
        throw "$($result.FailedCount) test(s) failed"
    }
    Write-Build Green "All $($result.PassedCount) test(s) passed"
}

task Docs Build, {
    Import-Module $ManifestPath -Force
    $null = New-Item -ItemType Directory -Path $DocsPath -Force
    New-MarkdownHelp -Module $ModuleName -OutputFolder $DocsPath -Force
    Write-Build Green "Documentation generated -> $DocsPath"
}

task CI Lint, Test, Build, {
    Write-Build Green "CI pipeline complete"
}

task . CI
