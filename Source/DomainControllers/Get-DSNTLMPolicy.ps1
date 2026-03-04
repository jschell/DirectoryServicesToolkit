function Get-DSNTLMPolicy
{
<#
.SYNOPSIS
Retrieves NTLM authentication policy settings from each domain controller's registry.

.DESCRIPTION
Reads LmCompatibilityLevel, NoLMHash, NtlmMinClientSec, and NtlmMinServerSec from
HKLM\SYSTEM\CurrentControlSet\Control\Lsa on each domain controller. LmCompatibilityLevel
below 5 indicates NTLMv1 authentication may be permitted, which is cryptographically weak.
LmCompatibilityLevel values: 0-2 = NTLMv1 permitted (Critical), 3-4 = NTLMv2 preferred
but NTLMv1 may be accepted (Medium), 5 = NTLMv2 only everywhere (Compliant). Inconsistent
settings across DCs are a notable finding. Requires RemoteRegistry service on each DC.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Get-DSNTLMPolicy -Domain 'contoso.com'

Returns NTLM policy configuration for each DC in contoso.com.

.EXAMPLE
Get-DSNTLMPolicy -Domain 'contoso.com' | Where-Object { $_.LmCompatibilityLevel -lt 5 }

Returns DCs with sub-optimal NTLM configuration.

.NOTES
#### Name:    Get-DSNTLMPolicy
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-04::0.1.0
- Initial creation
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

        Write-Verbose "Checking NTLM policy on $($dcNames.Count) domain controller(s)"

        $registryPath = 'SYSTEM\CurrentControlSet\Control\Lsa'

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        foreach ($dc in $dcNames)
        {
            Write-Verbose "Querying NTLM policy on: $dc"

            $lmCompat     = $null
            $noLMHash     = $null
            $minClientSec = $null
            $minServerSec = $null
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
                    $lmCompat     = $subKey.GetValue('LmCompatibilityLevel')
                    $noLMHash     = $subKey.GetValue('NoLMHash')
                    $minClientSec = $subKey.GetValue('NtlmMinClientSec')
                    $minServerSec = $subKey.GetValue('NtlmMinServerSec')
                    $subKey.Close()
                }

                $regBase.Close()
            }
            catch
            {
                $errorMessage = "Registry access failed: $_"
                Write-Verbose "Could not query registry on '$dc': $_"
            }

            # Default when absent: LmCompatibilityLevel defaults to 3 on modern Windows
            if ($null -eq $lmCompat) { $lmCompat = 3 }
            if ($null -eq $noLMHash) { $noLMHash  = 0 }

            $lmCompatInt = [int]$lmCompat

            $riskLevel = if ($lmCompatInt -le 2) { 'Critical' }
                         elseif ($lmCompatInt -le 4) { 'Medium' }
                         elseif ($lmCompatInt -eq 5) { 'Compliant' }
                         else { 'Unknown' }

            $lmDescription = switch ($lmCompatInt)
            {
                0       { 'Send LM and NTLM — NTLMv1 and LM hash permitted' }
                1       { 'Send LM and NTLM with session security — NTLMv1 permitted' }
                2       { 'Send NTLM only — NTLMv1 still accepted by server' }
                3       { 'Send NTLMv2 only from clients — NTLMv1 accepted by server' }
                4       { 'Send NTLMv2 only — refuse NTLMv1 from clients' }
                5       { 'Send NTLMv2 only — refuse LM and NTLMv1 everywhere' }
                default { "Unknown level: $lmCompatInt" }
            }

            # NtlmMinSec bitmask flags
            $ntlmv2Client   = if ($null -ne $minClientSec) { [bool]([int]$minClientSec -band 0x00080000) } else { $false }
            $enc128Client   = if ($null -ne $minClientSec) { [bool]([int]$minClientSec -band 0x20000000) } else { $false }
            $ntlmv2Server   = if ($null -ne $minServerSec) { [bool]([int]$minServerSec -band 0x00080000) } else { $false }
            $enc128Server   = if ($null -ne $minServerSec) { [bool]([int]$minServerSec -band 0x20000000) } else { $false }

            [void]$results.Add(
                [PSCustomObject]@{
                    DCName                 = $dc
                    LmCompatibilityLevel   = $lmCompatInt
                    LmCompatDescription    = $lmDescription
                    NoLMHash               = [bool]([int]$noLMHash -eq 1)
                    NtlmMinClientSec       = if ($null -ne $minClientSec) { [int]$minClientSec } else { $null }
                    NtlmMinServerSec       = if ($null -ne $minServerSec) { [int]$minServerSec } else { $null }
                    NTLMv2ClientRequired   = $ntlmv2Client
                    Encryption128BitClient = $enc128Client
                    NTLMv2ServerRequired   = $ntlmv2Server
                    Encryption128BitServer = $enc128Server
                    RiskLevel              = $riskLevel
                    IsCompliant            = ($riskLevel -eq 'Compliant')
                    ErrorMessage           = $errorMessage
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property IsCompliant, DCName
    }
}
