function Test-DSCachedCredentialPolicy
{
<#
.SYNOPSIS
Checks the cached domain credential count policy on each domain controller.

.DESCRIPTION
Reads the CachedLogonsCount registry value from:
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon

This setting controls how many previous domain user logons are cached locally as
hashes. Cached credentials allow domain users to log in when no DC is reachable.
However, cached credential hashes (MSCACHE v2) are stored in the SAM hive and can
be extracted and offline-cracked by an attacker with local SYSTEM access.

NIST 800-171 and CMMC recommend setting this to 0 on domain controllers (DCs do not
need cached credentials — they are always online), and to 1 or fewer on workstations.

Risk classification:
  CachedLogonsCount = 0                → Low (no caching)
  CachedLogonsCount = 1-2              → Medium (minimal caching)
  CachedLogonsCount > 2 or key absent  → High (excessive caching)

Requires RemoteRegistry service running on each DC and remote registry read access.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Test-DSCachedCredentialPolicy -Domain 'contoso.com'

Returns the cached credential policy for each DC in contoso.com.

.EXAMPLE
Test-DSCachedCredentialPolicy | Where-Object { -not $_.IsCompliant }

Returns domain controllers where cached credentials may expose credential material.

.NOTES
#### Name:    Test-DSCachedCredentialPolicy
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-08::0.1.0
- Initial creation — cached credential count policy check per DC

NIST 800-53: IA-5(13), SC-28
NIST 800-207: Identity pillar — credential protection at rest
CMMC Level 3: 3.5.10 (store only cryptographically-protected passwords)

.LINK
https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-number-of-previous-logons-to-cache
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

        Write-Verbose "Checking cached credential policy on $($dcNames.Count) domain controller(s)"

        $registryPath = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        foreach ($dc in $dcNames)
        {
            Write-Verbose "Querying CachedLogonsCount on: $dc"

            $rawValue    = $null
            $errorMessage = $null

            try
            {
                $regBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine,
                    $dc
                )
                $subKey = $regBase.OpenSubKey($registryPath)

                if ($null -ne $subKey)
                {
                    $rawValue = $subKey.GetValue('CachedLogonsCount')
                    $subKey.Close()
                }

                $regBase.Close()
            }
            catch
            {
                $errorMessage = "Registry access failed: $_"
                Write-Verbose "Could not query registry on '$dc': $_"
            }

            # Key absent defaults to 10 on most Windows versions
            $cachedCount = if ($null -ne $rawValue) { [int]$rawValue } else { $null }

            $riskLevel = if ($null -ne $errorMessage -and $null -eq $cachedCount)
            {
                'Unknown'
            }
            elseif ($null -eq $cachedCount)
            {
                'High'   # Absent = OS default (10) — excessive for a DC
            }
            elseif ($cachedCount -eq 0)
            {
                'Low'
            }
            elseif ($cachedCount -le 2)
            {
                'Medium'
            }
            else
            {
                'High'
            }

            $description = if ($riskLevel -eq 'Low')
            {
                'Cached credentials disabled — no MSCACHE hashes stored on this DC'
            }
            elseif ($riskLevel -eq 'Medium')
            {
                "CachedLogonsCount=$cachedCount — minimal caching, MSCACHE hashes present but limited"
            }
            elseif ($null -eq $cachedCount)
            {
                'CachedLogonsCount not set — OS default (10) applies, excessive for a DC'
            }
            else
            {
                "CachedLogonsCount=$cachedCount — excessive credential caching, MSCACHE hashes crackable offline"
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    DCName           = $dc
                    CachedLogonsCount = $cachedCount
                    Description      = $description
                    RiskLevel        = $riskLevel
                    IsCompliant      = ($riskLevel -eq 'Low')
                    ErrorMessage     = $errorMessage
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property IsCompliant, DCName
    }
}
