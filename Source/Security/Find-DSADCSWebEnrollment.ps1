function Find-DSADCSWebEnrollment
{
<#
.SYNOPSIS
Detects CA servers with HTTP (non-HTTPS) web enrollment endpoints exposed (ESC8).

.DESCRIPTION
Identifies CA web enrollment endpoints configured for HTTP (non-HTTPS) which can be
used as NTLM relay targets (ESC8). An attacker who can coerce NTLM authentication
from a privileged account and relay it to an HTTP enrollment endpoint can obtain a
certificate for that account.

Requires read access to the Configuration naming context.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Find-DSADCSWebEnrollment -Domain 'contoso.com'

Returns all web enrollment endpoints for CA servers in the contoso.com domain,
with HTTP endpoints flagged as NTLM relay candidates.

.EXAMPLE
Find-DSADCSWebEnrollment -Domain 'contoso.com' | Where-Object { $_.NTLMRelayRisk }

Returns only HTTP endpoints at risk of NTLM relay attacks (ESC8).

.NOTES
#### Name:    Find-DSADCSWebEnrollment
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
            $DomainName = Resolve-DSDomainName -Domain $Domain
        }
        catch
        {
            Write-Error "Cannot connect to domain '$Domain': $_"
            return
        }

        Write-Verbose "Querying domain: $DomainName for CA web enrollment endpoints"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $configNC = "CN=Configuration,$domainDN"

        $ldapPath   = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        $ldapFilter = '(objectClass=pKIEnrollmentService)'
        $properties = @(
            'name'
            'distinguishedName'
            'dNSHostName'
            'msPKI-Enrollment-Servers'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $queryResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($obj in $queryResults)
        {
            $enrollSvrs = if ($null -ne $obj['mspki-enrollment-servers']) { @($obj['mspki-enrollment-servers']) } else { @() }

            if ($enrollSvrs.Count -eq 0)
            {
                continue
            }

            foreach ($endpoint in $enrollSvrs)
            {
                $isHTTP  = $endpoint -match '^http://'
                $isHTTPS = $endpoint -match '^https://'

                [void]$results.Add(
                    [PSCustomObject]@{
                        CAName        = [string]$obj['name'][0]
                        DNSHostName   = if ($null -ne $obj['dnshostname'][0]) { [string]$obj['dnshostname'][0] } else { $null }
                        EndpointURL   = $endpoint
                        Protocol      = if ($isHTTPS) { 'HTTPS' } elseif ($isHTTP) { 'HTTP' } else { 'Unknown' }
                        IsHTTPOnly    = $isHTTP
                        NTLMRelayRisk = $isHTTP
                        RiskLevel     = if ($isHTTP) { 'Critical' } else { 'Informational' }
                        Finding       = if ($isHTTP) { "HTTP enrollment endpoint '$endpoint' on CA '$([string]$obj['name'][0])' is vulnerable to NTLM relay (ESC8)" } else { 'HTTPS enrollment endpoint — lower relay risk' }
                    }
                )
            }
        }
    }

    End
    {
        $results | Sort-Object -Property NTLMRelayRisk -Descending
    }
}
