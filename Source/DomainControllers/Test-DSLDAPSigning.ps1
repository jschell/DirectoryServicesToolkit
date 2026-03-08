function Test-DSLDAPSigning
{
<#
.SYNOPSIS
Queries each domain controller to assess the LDAP server signing requirement policy.

.DESCRIPTION
Reads HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\ldap server integrity
from each domain controller's registry. Values: 0 = None (Critical — unsigned LDAP
permitted), 1 = Negotiate signing (Medium — signing not enforced), 2 = Require signing
(Compliant). Domain controllers not requiring LDAP signing are vulnerable to NTLM relay
attacks targeting LDAP. Requires the RemoteRegistry service to be running on each DC
and an account with remote registry read rights.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Test-DSLDAPSigning -Domain 'contoso.com'

Returns the LDAP signing policy for each DC in contoso.com.

.EXAMPLE
Test-DSLDAPSigning -Domain 'contoso.com' | Where-Object { -not $_.IsCompliant }

Returns only non-compliant domain controllers.

.NOTES
#### Name:    Test-DSLDAPSigning
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

        Write-Verbose "Checking LDAP signing policy on $($dcNames.Count) domain controller(s)"

        $registryPath = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        $valueName    = 'ldap server integrity'

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        foreach ($dc in $dcNames)
        {
            Write-Verbose "Querying LDAP signing policy on: $dc"

            $signingValue = $null
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
                    $signingValue = $subKey.GetValue($valueName)
                    $subKey.Close()
                }

                $regBase.Close()
            }
            catch
            {
                $errorMessage = "Registry access failed: $_"
                Write-Verbose "Could not query registry on '$dc': $_"
            }

            # When key is absent the effective default is Negotiate (1)
            if ($null -eq $signingValue) { $signingValue = 1 }

            $signingInt = [int]$signingValue

            $riskLevel  = switch ($signingInt)
            {
                0       { 'Critical' }
                1       { 'Medium' }
                2       { 'Low' }
                default { 'Unknown' }
            }

            $description = switch ($signingInt)
            {
                0       { 'No signing required — unsigned LDAP permitted' }
                1       { 'Negotiate signing — signing not enforced' }
                2       { 'Require signing — LDAP signing enforced' }
                default { "Unrecognized value: $signingInt" }
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    DCName       = $dc
                    SigningValue = $signingInt
                    Description  = $description
                    RiskLevel    = $riskLevel
                    IsCompliant  = ($riskLevel -eq 'Low')
                    ErrorMessage = $errorMessage
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property IsCompliant, DCName
    }
}
