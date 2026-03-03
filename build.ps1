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
  Invoke-Build Build    - Compile module to Output/
  Invoke-Build Docs     - Generate platyPS markdown docs
  Invoke-Build CI       - Full pipeline: Lint -> Test -> Build
  Invoke-Build Clean    - Remove build artifacts
#>

$ModuleName    = 'DirectoryServicesToolkit'
$SourcePath    = "$PSScriptRoot/Source"
$OutputPath    = "$PSScriptRoot/Output"
$TestPath      = "$PSScriptRoot/Tests"
$DocsPath      = "$PSScriptRoot/Docs/en-US"
$ManifestPath  = "$OutputPath/$ModuleName.psd1"
$ModulePath    = "$OutputPath/$ModuleName.psm1"
$AnalyzerSettings = "$PSScriptRoot/PSScriptAnalyzerSettings.psd1"

# ── Helper ──────────────────────────────────────────────────────────────────

function Get-PublicFunctions
{
    Get-ChildItem -Path $SourcePath -Recurse -Filter '*.ps1' |
        Where-Object { $_.DirectoryName -notmatch '\\Private$' -and
                       $_.DirectoryName -notmatch '/Private$' } |
        ForEach-Object { $_.BaseName }
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

    # Concatenate all ps1 files into the root psm1
    $psm1Content = [System.Text.StringBuilder]::new()

    Get-ChildItem -Path $SourcePath -Recurse -Filter '*.ps1' |
        Where-Object { $_.DirectoryName -notmatch '\\Private$' -and
                       $_.DirectoryName -notmatch '/Private$' } |
        Sort-Object FullName |
        ForEach-Object {
            $null = $psm1Content.AppendLine(". `$PSScriptRoot/$($_.Name)")
            Copy-Item -Path $_.FullName -Destination $OutputPath -Force
        }

    # Copy private functions
    $privatePath = Join-Path $SourcePath 'Private'
    if (Test-Path $privatePath)
    {
        Get-ChildItem -Path $privatePath -Filter '*.ps1' | ForEach-Object {
            $null = $psm1Content.AppendLine(". `$PSScriptRoot/Private/$($_.Name)")
        }
        $privateOut = Join-Path $OutputPath 'Private'
        $null = New-Item -ItemType Directory -Path $privateOut -Force
        Copy-Item -Path "$privatePath/*.ps1" -Destination $privateOut -Force
    }

    $psm1Content.ToString() | Set-Content -Path $ModulePath -Encoding UTF8

    # Determine highest function version for module version
    $versionPattern = '####\s+Version:\s+([\d.]+)'
    $highestVersion = '0.1.0'
    Get-ChildItem -Path $SourcePath -Recurse -Filter '*.ps1' | ForEach-Object {
        $content = Get-Content $_.FullName -Raw
        if ($content -match $versionPattern)
        {
            if ([version]$Matches[1] -gt [version]$highestVersion)
            {
                $highestVersion = $Matches[1]
            }
        }
    }

    $publicFunctions = Get-PublicFunctions

    $manifestParams = @{
        Path              = $ManifestPath
        ModuleVersion     = $highestVersion
        Author            = 'J Schell'
        Description       = 'Active Directory security assessment and operational toolkit'
        PowerShellVersion = '7.0'
        RootModule        = "$ModuleName.psm1"
        FunctionsToExport = $publicFunctions
        Tags              = @('ActiveDirectory', 'Security', 'Audit', 'DirectoryServices')
        LicenseUri        = 'https://opensource.org/licenses/MIT'
        ProjectUri        = 'https://github.com/jschell/DirectoryServicesToolkit'
    }
    New-ModuleManifest @manifestParams
    Write-Build Green "Built $ModuleName v$highestVersion -> $OutputPath"
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
