function Invoke-DSBaselineCapture
{
<#
.SYNOPSIS
Snapshots the current AD state across key security indicators to a JSON file.

.DESCRIPTION
Captures a point-in-time baseline of the Active Directory environment by
running a configurable set of toolkit functions and serializing their output
to a structured JSON file with a timestamp.

Captured indicators include (by default):
  - Privileged group membership (Get-DSAdminAccounts)
  - Delegation configurations (Find-DSDelegation)
  - Trust relationships (Get-DSTrustRelationship)
  - Password policy (Get-DSPasswordPolicy)
  - Kerberoastable accounts (Find-DSKerberoastable)
  - AS-REP roastable accounts (Find-DSASREPRoastable)
  - AdminSDHolder anomalies (Get-DSAdminSDHolder)

The output file is named with the domain and UTC timestamp for easy comparison.
Use Compare-DSBaseline to diff two captured baselines.

.PARAMETER Domain
The DNS name of the domain to baseline. Defaults to the current user's domain.

.PARAMETER OutputPath
Directory where the baseline JSON file is written. Defaults to the current
working directory.

.PARAMETER Indicators
List of indicator names to capture. Defaults to the full standard set.
Use this parameter to capture a subset for faster runs.

.EXAMPLE
Invoke-DSBaselineCapture -Domain 'contoso.com' -OutputPath C:\Baselines

Captures a full baseline of contoso.com and writes it to C:\Baselines.

.EXAMPLE
Invoke-DSBaselineCapture -Indicators 'AdminAccounts','Trusts'

Captures only admin accounts and trust configurations.

.NOTES
#### Name:    Invoke-DSBaselineCapture
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-03::0.1.0
- Initial creation
#>

    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = $PWD,

        [Parameter()]
        [ValidateSet(
            'AdminAccounts', 'Delegation', 'Trusts', 'PasswordPolicy',
            'Kerberoastable', 'ASREPRoastable', 'AdminSDHolder'
        )]
        [string[]]$Indicators = @(
            'AdminAccounts', 'Delegation', 'Trusts', 'PasswordPolicy',
            'Kerberoastable', 'ASREPRoastable', 'AdminSDHolder'
        )
    )

    Begin
    {
        # Validate and create output directory if needed
        if (-not (Test-Path -LiteralPath $OutputPath))
        {
            try
            {
                [void](New-Item -ItemType Directory -Path $OutputPath -Force)
                Write-Verbose "Created output directory: $OutputPath"
            }
            catch
            {
                Write-Error "Cannot create output directory '$OutputPath': $_"
                return
            }
        }

        $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH-mm-ssZ')
        $fileName  = '{0}-baseline-{1}.json' -f ($Domain -replace '[^\w\.]', '_'), $timestamp
        $fullPath  = Join-Path $OutputPath $fileName

        # Indicator → function name mapping
        $indicatorMap = @{
            AdminAccounts  = 'Get-DSAdminAccounts'
            Delegation     = 'Find-DSDelegation'
            Trusts         = 'Get-DSTrustRelationship'
            PasswordPolicy = 'Get-DSPasswordPolicy'
            Kerberoastable = 'Find-DSKerberoastable'
            ASREPRoastable = 'Find-DSASREPRoastable'
            AdminSDHolder  = 'Get-DSAdminSDHolder'
        }

        $snapshot = [ordered]@{
            Schema        = '1.0'
            CapturedAt    = (Get-Date).ToUniversalTime().ToString('o')
            Domain        = $Domain
            Indicators    = [ordered]@{}
            CaptureErrors = [ordered]@{}
        }

        Write-Verbose "Starting baseline capture for domain: $Domain"
        Write-Verbose "Output file: $fullPath"
    }

    Process
    {
        foreach ($indicator in $Indicators)
        {
            $funcName = $indicatorMap[$indicator]
            Write-Verbose "Capturing indicator: $indicator ($funcName)"

            try
            {
                $result = & $funcName -Domain $Domain
                $snapshot.Indicators[$indicator] = $result
            }
            catch
            {
                $snapshot.CaptureErrors[$indicator] = $_.Exception.Message
                Write-Warning "Failed to capture '$indicator': $_"
            }
        }
    }

    End
    {
        try
        {
            $snapshot | ConvertTo-Json -Depth 10 | Set-Content -Path $fullPath -Encoding UTF8
            Write-Verbose "Baseline written to: $fullPath"
            $fullPath
        }
        catch
        {
            Write-Error "Failed to write baseline file '$fullPath': $_"
        }
    }
}
