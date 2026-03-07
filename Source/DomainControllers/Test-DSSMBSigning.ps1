function Test-DSSMBSigning
{
<#
.SYNOPSIS
Queries each domain controller to assess SMB signing enforcement policy.

.DESCRIPTION
Reads RequireSecuritySignature and EnableSecuritySignature from the LanManServer
registry key on each domain controller:
  HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters

A domain controller with LDAP signing enforced but SMB signing not required remains
relay-exploitable. SMBRelay and similar tools can coerce NTLM authentication over
SMB and relay it to other services if the target does not require signed connections.

Risk assessment:
  RequireSecuritySignature = 1                   → Compliant
  RequireSecuritySignature = 0, Enabled = 1      → Medium (negotiated but not enforced)
  RequireSecuritySignature = 0, Enabled = 0      → Critical (unsigned SMB accepted)

Requires RemoteRegistry to be running on each DC and an account with remote
registry read rights.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Test-DSSMBSigning -Domain 'contoso.com'

Returns the SMB signing enforcement policy for each DC in contoso.com.

.EXAMPLE
Test-DSSMBSigning | Where-Object { -not $_.IsCompliant }

Returns only domain controllers where SMB signing is not required.

.NOTES
#### Name:    Test-DSSMBSigning
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-07::0.1.0
- Initial creation — registry-based SMB signing enforcement check per DC

.LINK
https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview
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

        Write-Verbose "Checking SMB signing policy on $($dcNames.Count) domain controller(s)"

        $registryPath = 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        foreach ($dc in $dcNames)
        {
            Write-Verbose "Querying SMB signing policy on: $dc"

            $requireValue = $null
            $enableValue  = $null
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
                    $requireValue = $subKey.GetValue('RequireSecuritySignature')
                    $enableValue  = $subKey.GetValue('EnableSecuritySignature')
                    $subKey.Close()
                }

                $regBase.Close()
            }
            catch
            {
                $errorMessage = "Registry access failed: $_"
                Write-Verbose "Could not query registry on '$dc': $_"
            }

            # When key is absent the effective default differs by Windows version:
            # On Server 2022+ RequireSecuritySignature defaults to 1 (required).
            # On older versions it defaults to 0. Use absent-key = 0 as safe conservative default.
            $requireInt = if ($null -ne $requireValue) { [int]$requireValue } else { 0 }
            $enableInt  = if ($null -ne $enableValue)  { [int]$enableValue  } else { 0 }

            $riskLevel = if ($requireInt -eq 1)
            {
                'Compliant'
            }
            elseif ($enableInt -eq 1)
            {
                'Medium'
            }
            else
            {
                'Critical'
            }

            $description = if ($requireInt -eq 1)
            {
                'SMB signing required — all SMB connections must be signed'
            }
            elseif ($enableInt -eq 1)
            {
                'SMB signing enabled but not required — signing negotiated, relay possible against non-signing clients'
            }
            else
            {
                'SMB signing not required and not enabled — unsigned SMB accepted, relay-exploitable'
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    DCName                    = $dc
                    RequireSecuritySignature  = $requireInt
                    EnableSecuritySignature   = $enableInt
                    Description               = $description
                    RiskLevel                 = $riskLevel
                    IsCompliant               = ($riskLevel -eq 'Compliant')
                    ErrorMessage              = $errorMessage
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property IsCompliant, DCName
    }
}
