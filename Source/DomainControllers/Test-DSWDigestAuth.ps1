function Test-DSWDigestAuth
{
<#
.SYNOPSIS
Checks whether WDigest authentication is enabled on each domain controller.

.DESCRIPTION
Reads the UseLogonCredential registry value from:
  HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest

When UseLogonCredential is set to 1, Windows stores cleartext credentials in LSASS
memory. Mimikatz and similar tools can extract these credentials from a process dump.

On Windows 8.1 / Server 2012 R2 and later, WDigest is disabled by default (key absent
or value 0). Older systems may have it enabled explicitly, or group policy may override
the default.

Risk classification:
  UseLogonCredential = 0 or key absent  → Low (cleartext creds not cached)
  UseLogonCredential = 1                → Critical (cleartext creds in LSASS)
  Registry inaccessible                 → Unknown

Requires RemoteRegistry service running on each DC and remote registry read access.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Test-DSWDigestAuth -Domain 'contoso.com'

Returns WDigest authentication status for each DC in contoso.com.

.EXAMPLE
Test-DSWDigestAuth | Where-Object { $_.RiskLevel -eq 'Critical' }

Returns domain controllers where WDigest is actively exposing cleartext credentials.

.NOTES
#### Name:    Test-DSWDigestAuth
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-08::0.1.0
- Initial creation — WDigest cleartext credential exposure check per DC

NIST 800-53: IA-5(1), SC-28, SC-8
NIST 800-207: Identity pillar — credential hygiene
CMMC Level 3: 3.5.10 (store and transmit only cryptographically-protected passwords)

.LINK
https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/prevent-windows-store-lm-hash-password
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

        Write-Verbose "Checking WDigest authentication on $($dcNames.Count) domain controller(s)"

        $registryPath = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        foreach ($dc in $dcNames)
        {
            Write-Verbose "Querying WDigest setting on: $dc"

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
                    $rawValue = $subKey.GetValue('UseLogonCredential')
                    $subKey.Close()
                }

                $regBase.Close()
            }
            catch
            {
                $errorMessage = "Registry access failed: $_"
                Write-Verbose "Could not query registry on '$dc': $_"
            }

            # Key absent = default disabled on modern OS
            $useLogonCredential = if ($null -ne $rawValue) { [int]$rawValue } else { $null }

            $riskLevel = if ($null -ne $errorMessage -and $null -eq $useLogonCredential)
            {
                'Unknown'
            }
            elseif ($null -eq $useLogonCredential -or $useLogonCredential -eq 0)
            {
                'Low'
            }
            else
            {
                'Critical'
            }

            $description = switch ($riskLevel)
            {
                'Low'      { 'WDigest disabled — cleartext credentials not cached in LSASS' }
                'Critical' { 'WDigest enabled — cleartext credentials stored in LSASS memory, credential extraction possible' }
                'Unknown'  { 'WDigest status unknown — registry inaccessible' }
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    DCName              = $dc
                    UseLogonCredential  = $useLogonCredential
                    WDigestEnabled      = ($riskLevel -eq 'Critical')
                    Description         = $description
                    RiskLevel           = $riskLevel
                    IsCompliant         = ($riskLevel -eq 'Low')
                    ErrorMessage        = $errorMessage
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property IsCompliant, DCName
    }
}
