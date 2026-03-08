function Test-DSRemoteManagementSecurity
{
<#
.SYNOPSIS
Checks RDP Network Level Authentication and WinRM encryption settings on each DC.

.DESCRIPTION
Evaluates two remote management security controls per domain controller:

1. Remote Desktop / RDP settings (HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp):
   - UserAuthentication   (NLA enforcement): 1 = required, 0 = not required
   - SecurityLayer:       2 = SSL/TLS, 1 = Negotiate, 0 = RDP native only
   - MinEncryptionLevel:  4 = FIPS, 3 = High, 2 = Client compatible, 1 = Low

2. WinRM security (HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service):
   - AllowUnencrypted: 0 or absent = encrypted only, 1 = allows unencrypted traffic

Risk classification:
  NLA required, TLS, High/FIPS encryption, WinRM encrypted  → Low
  NLA not required OR SecurityLayer < 2                      → Medium
  NLA disabled AND SecurityLayer = 0 AND WinRM unencrypted   → High

Requires RemoteRegistry service running on each DC and remote registry read access.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Test-DSRemoteManagementSecurity -Domain 'contoso.com'

Returns remote management security posture for each DC.

.EXAMPLE
Test-DSRemoteManagementSecurity | Where-Object { -not $_.NLARequired }

Returns DCs not requiring Network Level Authentication for RDP.

.NOTES
#### Name:    Test-DSRemoteManagementSecurity
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-08::0.1.0
- Initial creation — RDP NLA and WinRM encryption check per DC

NIST 800-53: AC-17, SC-8, SC-13, IA-2(1)
NIST 800-207: Network pillar — encrypted access to management plane
CMMC Level 3: 3.1.12 (monitor and control remote access sessions), 3.13.8

.LINK
https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access
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

        Write-Verbose "Checking remote management security on $($dcNames.Count) domain controller(s)"

        $rdpRegPath   = 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $winrmRegPath = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        foreach ($dc in $dcNames)
        {
            Write-Verbose "Querying remote management security on: $dc"

            $nlaValue         = $null
            $secLayerValue    = $null
            $encLevelValue    = $null
            $winrmUnencrypted = $null
            $errorMessage     = $null

            try
            {
                $regBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine,
                    $dc
                )

                $rdpKey = $regBase.OpenSubKey($rdpRegPath)
                if ($null -ne $rdpKey)
                {
                    $nlaValue      = $rdpKey.GetValue('UserAuthentication')
                    $secLayerValue = $rdpKey.GetValue('SecurityLayer')
                    $encLevelValue = $rdpKey.GetValue('MinEncryptionLevel')
                    $rdpKey.Close()
                }

                $winrmKey = $regBase.OpenSubKey($winrmRegPath)
                if ($null -ne $winrmKey)
                {
                    $winrmUnencrypted = $winrmKey.GetValue('AllowUnencrypted')
                    $winrmKey.Close()
                }

                $regBase.Close()
            }
            catch
            {
                $errorMessage = "Registry access failed: $_"
                Write-Verbose "Could not query registry on '$dc': $_"
            }

            $nlaInt          = if ($null -ne $nlaValue)         { [int]$nlaValue }         else { 0 }
            $secLayerInt     = if ($null -ne $secLayerValue)    { [int]$secLayerValue }    else { 1 }
            $encLevelInt     = if ($null -ne $encLevelValue)    { [int]$encLevelValue }    else { 2 }
            $winrmUnencInt   = if ($null -ne $winrmUnencrypted) { [int]$winrmUnencrypted } else { 0 }

            $nlaRequired     = ($nlaInt -eq 1)
            $tlsEnabled      = ($secLayerInt -eq 2)
            $highEncryption  = ($encLevelInt -ge 3)
            $winrmEncrypted  = ($winrmUnencInt -eq 0)

            $issues = @()
            if (-not $nlaRequired)    { $issues += 'NLA not required for RDP (UserAuthentication=0)' }
            if (-not $tlsEnabled)     { $issues += "SecurityLayer=$secLayerInt — TLS not enforced (set to 2 for SSL/TLS)" }
            if (-not $highEncryption) { $issues += "MinEncryptionLevel=$encLevelInt — not High/FIPS (set to 3 or 4)" }
            if (-not $winrmEncrypted) { $issues += 'WinRM AllowUnencrypted=1 — unencrypted WinRM traffic accepted' }

            $riskLevel = if ($issues.Count -eq 0)
            {
                'Low'
            }
            elseif (-not $nlaRequired -and -not $tlsEnabled -and -not $winrmEncrypted)
            {
                'High'
            }
            elseif ($issues.Count -ge 2)
            {
                'Medium'
            }
            else
            {
                'Medium'
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    DCName              = $dc
                    NLARequired         = $nlaRequired
                    UserAuthentication  = $nlaInt
                    SecurityLayer       = $secLayerInt
                    MinEncryptionLevel  = $encLevelInt
                    TLSEnabled          = $tlsEnabled
                    HighEncryption      = $highEncryption
                    WinRMEncryptedOnly  = $winrmEncrypted
                    Issues              = $issues
                    IssueCount          = $issues.Count
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
