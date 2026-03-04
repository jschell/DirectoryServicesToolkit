function Test-DSLDAPChannelBinding
{
<#
.SYNOPSIS
Queries each domain controller to assess the LDAP channel binding token enforcement policy.

.DESCRIPTION
Reads HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding
from each domain controller's registry. Values: 0 = Disabled (Critical), 1 = Enabled when
supported (Medium), 2 = Always required (Compliant). Without channel binding enforcement,
LDAP over TLS connections remain vulnerable to NTLM relay even when the transport is
encrypted. Requires the RemoteRegistry service on each DC.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Test-DSLDAPChannelBinding -Domain 'contoso.com'

Returns channel binding policy for each DC in contoso.com.

.EXAMPLE
Test-DSLDAPChannelBinding -Domain 'contoso.com' | Where-Object { -not $_.IsCompliant }

Returns only non-compliant domain controllers.

.NOTES
#### Name:    Test-DSLDAPChannelBinding
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

        Write-Verbose "Checking LDAP channel binding policy on $($dcNames.Count) domain controller(s)"

        $registryPath = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        $valueName    = 'LdapEnforceChannelBinding'

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        foreach ($dc in $dcNames)
        {
            Write-Verbose "Querying channel binding policy on: $dc"

            $channelBindValue = $null
            $errorMessage     = $null

            try
            {
                $regBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine,
                    $dc
                )
                $subKey = $regBase.OpenSubKey($registryPath)

                if ($null -ne $subKey)
                {
                    $channelBindValue = $subKey.GetValue($valueName)
                    $subKey.Close()
                }

                $regBase.Close()
            }
            catch
            {
                $errorMessage = "Registry access failed: $_"
                Write-Verbose "Could not query registry on '$dc': $_"
            }

            # When absent the effective default is Disabled (0)
            if ($null -eq $channelBindValue) { $channelBindValue = 0 }

            $cbInt = [int]$channelBindValue

            $riskLevel = switch ($cbInt)
            {
                0       { 'Critical' }
                1       { 'Medium' }
                2       { 'Compliant' }
                default { 'Unknown' }
            }

            $description = switch ($cbInt)
            {
                0       { 'Disabled — channel binding not enforced' }
                1       { 'Enabled when supported — partial enforcement only' }
                2       { 'Always required — channel binding enforced' }
                default { "Unrecognized value: $cbInt" }
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    DCName               = $dc
                    ChannelBindingValue  = $cbInt
                    Description          = $description
                    RiskLevel            = $riskLevel
                    IsCompliant          = ($riskLevel -eq 'Compliant')
                    ErrorMessage         = $errorMessage
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property IsCompliant, DCName
    }
}
