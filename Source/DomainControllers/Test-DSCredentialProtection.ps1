function Test-DSCredentialProtection
{
<#
.SYNOPSIS
Checks pass-the-hash mitigations and Credential Guard status on each domain controller.

.DESCRIPTION
Evaluates three registry-based credential protection controls per domain controller:

1. LocalAccountTokenFilterPolicy (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System)
   Controls whether local admin tokens are filtered for network logons:
     0 or absent = Filtered (safe) — local admins get limited token over network
     1           = Not filtered (risky) — full admin token over network, enables PTH

2. DisableRestrictedAdmin (HKLM\System\CurrentControlSet\Control\Lsa)
   Controls whether Restricted Admin mode is available for RDP:
     0 or absent = Restricted Admin enabled (safe) — no credential delegation over RDP
     1           = Restricted Admin disabled (risky) — credentials delegated over RDP

3. LsaCfgFlags (HKLM\System\CurrentControlSet\Control\DeviceGuard)
   Controls Credential Guard (HVCI-based LSASS protection):
     0 or absent = Credential Guard disabled
     1           = Credential Guard enabled with UEFI lock
     2           = Credential Guard enabled without lock

Risk classification:
  All three controls optimal                        → Low
  One control misconfigured                         → Medium
  LocalAccountTokenFilterPolicy = 1                 → High  (PTH directly enabled)
  Multiple controls misconfigured                   → High

Requires RemoteRegistry service running on each DC and remote registry read access.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Test-DSCredentialProtection -Domain 'contoso.com'

Returns credential protection posture for each DC in contoso.com.

.EXAMPLE
Test-DSCredentialProtection | Where-Object { -not $_.IsCompliant }

Returns domain controllers with credential protection gaps.

.NOTES
#### Name:    Test-DSCredentialProtection
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-08::0.1.0
- Initial creation — PTH mitigation and Credential Guard check per DC

NIST 800-53: SC-8, SC-28, IA-2, IA-5(1)
NIST 800-207: Identity pillar — credential protection and isolation
CMMC Level 3: 3.5.3, 3.13.8, 3.13.10

.LINK
https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(HelpMessage = 'DNS name of the target domain')]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN
    )

    Begin
    {
        try
        {
            $dcNames = Get-DSDomainControllerNames -Domain $Domain
        }
        catch
        {
            Write-Error "Cannot enumerate domain controllers for '$Domain': $_"
            return
        }

        Write-Verbose "Checking credential protection on $($dcNames.Count) domain controller(s)"

        $lsaPath          = 'System\CurrentControlSet\Control\Lsa'
        $policiesPath     = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $deviceGuardPath  = 'System\CurrentControlSet\Control\DeviceGuard'

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        foreach ($dc in $dcNames)
        {
            Write-Verbose "Querying credential protection on: $dc"

            $latfpValue   = $null
            $draValue     = $null
            $cgFlagsValue = $null
            $errorMessage = $null

            try
            {
                $regBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine,
                    $dc
                )

                $policiesKey = $regBase.OpenSubKey($policiesPath)
                if ($null -ne $policiesKey)
                {
                    $latfpValue = $policiesKey.GetValue('LocalAccountTokenFilterPolicy')
                    $policiesKey.Close()
                }

                $lsaKey = $regBase.OpenSubKey($lsaPath)
                if ($null -ne $lsaKey)
                {
                    $draValue = $lsaKey.GetValue('DisableRestrictedAdmin')
                    $lsaKey.Close()
                }

                $dgKey = $regBase.OpenSubKey($deviceGuardPath)
                if ($null -ne $dgKey)
                {
                    $cgFlagsValue = $dgKey.GetValue('LsaCfgFlags')
                    $dgKey.Close()
                }

                $regBase.Close()
            }
            catch
            {
                $errorMessage = "Registry access failed: $_"
                Write-Verbose "Could not query registry on '$dc': $_"
            }

            $latfpInt   = if ($null -ne $latfpValue)   { [int]$latfpValue }   else { 0 }
            $draInt     = if ($null -ne $draValue)      { [int]$draValue }     else { 0 }
            $cgFlagsInt = if ($null -ne $cgFlagsValue)  { [int]$cgFlagsValue } else { 0 }

            $issues = @()

            if ($latfpInt -eq 1)
            {
                $issues += 'LocalAccountTokenFilterPolicy=1 enables pass-the-hash via network logon'
            }

            if ($draInt -eq 1)
            {
                $issues += 'DisableRestrictedAdmin=1 — credentials delegated over RDP (no Restricted Admin protection)'
            }

            if ($cgFlagsInt -eq 0)
            {
                $issues += 'Credential Guard not configured (LsaCfgFlags=0 or absent)'
            }

            $riskLevel = if ($latfpInt -eq 1 -and $issues.Count -gt 1)
            {
                'High'
            }
            elseif ($latfpInt -eq 1)
            {
                'High'
            }
            elseif ($issues.Count -ge 2)
            {
                'Medium'
            }
            elseif ($issues.Count -eq 1)
            {
                'Medium'
            }
            else
            {
                'Low'
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    DCName                          = $dc
                    LocalAccountTokenFilterPolicy   = $latfpInt
                    DisableRestrictedAdmin          = $draInt
                    CredentialGuardFlags            = $cgFlagsInt
                    CredentialGuardEnabled          = ($cgFlagsInt -gt 0)
                    Issues                          = $issues
                    IssueCount                      = $issues.Count
                    RiskLevel                       = $riskLevel
                    IsCompliant                     = ($riskLevel -eq 'Low')
                    ErrorMessage                    = $errorMessage
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property IsCompliant, DCName
    }
}
