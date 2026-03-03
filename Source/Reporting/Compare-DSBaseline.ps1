function Compare-DSBaseline
{
<#
.SYNOPSIS
Diffs two baseline captures to surface changes in the AD environment.

.DESCRIPTION
Compares two JSON baseline files produced by Invoke-DSBaselineCapture and
reports changes across all captured indicators, including:

  - New accounts added to privileged groups
  - Accounts removed from privileged groups
  - New delegation configurations added
  - Delegation configurations removed or modified
  - New trusts created or trust attributes changed
  - New SPNs added (new Kerberoastable candidates)
  - Password policy changes
  - New AdminSDHolder anomalies

Output is a structured object containing Added, Removed, and Modified
collections per indicator, suitable for piping to New-DSAssessmentReport
or formatting directly.

.PARAMETER BaselinePath
Path to the earlier (reference) baseline JSON file.

.PARAMETER CurrentPath
Path to the later (comparison) baseline JSON file.

.PARAMETER Indicator
One or more indicator names to compare. Defaults to all indicators present
in both files.

.EXAMPLE
Compare-DSBaseline -BaselinePath C:\Baselines\contoso-2026-01-01.json `
                   -CurrentPath  C:\Baselines\contoso-2026-03-01.json

Compares two baselines and returns a diff across all indicators.

.EXAMPLE
Compare-DSBaseline -BaselinePath .\baseline-old.json `
                   -CurrentPath  .\baseline-new.json `
                   -Indicator AdminAccounts, Trusts

Compares only admin account and trust changes between the two baselines.

.NOTES
#### Name:    Compare-DSBaseline
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-03::0.1.0
- Initial creation
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaselinePath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CurrentPath,

        [Parameter()]
        [string[]]$Indicator
    )

    Begin
    {
        # Load and validate both JSON files
        try
        {
            $baselineContent = Get-Content -LiteralPath $BaselinePath -Raw -Encoding UTF8
            $baseline        = $baselineContent | ConvertFrom-Json
        }
        catch
        {
            Write-Error "Cannot read baseline file '$BaselinePath': $_"
            return
        }

        try
        {
            $currentContent = Get-Content -LiteralPath $CurrentPath -Raw -Encoding UTF8
            $current        = $currentContent | ConvertFrom-Json
        }
        catch
        {
            Write-Error "Cannot read current file '$CurrentPath': $_"
            return
        }

        # Schema version check
        if ($baseline.Schema -ne '1.0' -or $current.Schema -ne '1.0')
        {
            Write-Warning 'One or both baseline files have an unexpected Schema version. Results may be inaccurate.'
        }

        # Identity key per indicator — used to match items across snapshots
        $identityKeyMap = @{
            AdminAccounts  = 'DistinguishedName'
            Delegation     = 'DistinguishedName'   # composite handled below
            Trusts         = 'Name'
            PasswordPolicy = 'Name'
            Kerberoastable = 'DistinguishedName'
            ASREPRoastable = 'DistinguishedName'
            AdminSDHolder  = 'DistinguishedName'
        }

        # Delegation uses a composite key to distinguish delegation type per object
        $compositeKeyIndicators = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        [void]$compositeKeyIndicators.Add('Delegation')

        # Determine which indicators to compare
        $baselineIndicatorNames = @($baseline.Indicators.PSObject.Properties.Name)
        $currentIndicatorNames  = @($current.Indicators.PSObject.Properties.Name)
        $allIndicatorNames      = ($baselineIndicatorNames + $currentIndicatorNames) | Sort-Object -Unique

        if ($Indicator -and $Indicator.Count -gt 0)
        {
            foreach ($reqInd in $Indicator)
            {
                if ($reqInd -notin $baselineIndicatorNames)
                {
                    Write-Warning "Indicator '$reqInd' not found in baseline file."
                }
                if ($reqInd -notin $currentIndicatorNames)
                {
                    Write-Warning "Indicator '$reqInd' not found in current file."
                }
            }
            $allIndicatorNames = $Indicator
        }

        $diffs         = [ordered]@{}
        $totalAdded    = 0
        $totalRemoved  = 0
        $totalModified = 0
    }

    Process
    {
        foreach ($ind in $allIndicatorNames)
        {
            $identityKey = if ($identityKeyMap.ContainsKey($ind)) { $identityKeyMap[$ind] } else { 'DistinguishedName' }
            $isComposite = $compositeKeyIndicators.Contains($ind)

            $baselineItems = @($baseline.Indicators.$ind)
            $currentItems  = @($current.Indicators.$ind)

            # Build lookup maps keyed by identity value
            $baselineMap = @{}
            foreach ($item in $baselineItems)
            {
                if ($null -eq $item) { continue }
                $key = if ($isComposite)
                {
                    '{0}|{1}' -f $item.$identityKey, $item.DelegationType
                }
                else
                {
                    [string]$item.$identityKey
                }
                if ($key) { $baselineMap[$key] = $item }
            }

            $currentMap = @{}
            foreach ($item in $currentItems)
            {
                if ($null -eq $item) { continue }
                $key = if ($isComposite)
                {
                    '{0}|{1}' -f $item.$identityKey, $item.DelegationType
                }
                else
                {
                    [string]$item.$identityKey
                }
                if ($key) { $currentMap[$key] = $item }
            }

            # Compute diff
            $added   = @($currentMap.Keys | Where-Object { -not $baselineMap.ContainsKey($_) } |
                         ForEach-Object { $currentMap[$_] })

            $removed = @($baselineMap.Keys | Where-Object { -not $currentMap.ContainsKey($_) } |
                         ForEach-Object { $baselineMap[$_] })

            $modified = @($currentMap.Keys | Where-Object { $baselineMap.ContainsKey($_) } | ForEach-Object {
                $b = $baselineMap[$_] | ConvertTo-Json -Depth 5 -Compress
                $c = $currentMap[$_]  | ConvertTo-Json -Depth 5 -Compress
                if ($b -ne $c)
                {
                    [PSCustomObject]@{
                        Baseline = $baselineMap[$_]
                        Current  = $currentMap[$_]
                    }
                }
            })

            $diffs[$ind] = [PSCustomObject]@{
                Added    = $added
                Removed  = $removed
                Modified = $modified
            }

            $totalAdded    += $added.Count
            $totalRemoved  += $removed.Count
            $totalModified += $modified.Count
        }
    }

    End
    {
        [PSCustomObject]@{
            BaselineCapturedAt = $baseline.CapturedAt
            CurrentCapturedAt  = $current.CapturedAt
            Domain             = $baseline.Domain
            Diffs              = $diffs
            Summary            = [PSCustomObject]@{
                TotalAdded    = $totalAdded
                TotalRemoved  = $totalRemoved
                TotalModified = $totalModified
                HasChanges    = ($totalAdded -gt 0 -or $totalRemoved -gt 0 -or $totalModified -gt 0)
            }
        }
    }
}
