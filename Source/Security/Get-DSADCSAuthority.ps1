function Get-DSADCSAuthority
{
<#
.SYNOPSIS
Enumerates Enterprise Certificate Authority servers from the Enrollment Services container.

.DESCRIPTION
Enumerates Enterprise Certificate Authority (CA) servers registered in the Enrollment
Services container of the Configuration naming context. Returns CA name, DNS hostname,
certificate expiry, CA type, and web enrollment endpoint details.

HTTP (non-HTTPS) enrollment endpoints are flagged as potential NTLM relay targets
(ESC8).

Requires read access to the Configuration naming context.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Get-DSADCSAuthority -Domain 'contoso.com'

Returns all Enterprise CA servers registered in the contoso.com domain along with
their enrollment endpoint details.

.EXAMPLE
Get-DSADCSAuthority -Domain 'contoso.com' | Where-Object { $_.HTTPEndpointCount -gt 0 }

Returns only CA servers with HTTP (non-HTTPS) enrollment endpoints exposed, which
are candidates for ESC8 NTLM relay attacks.

.NOTES
#### Name:    Get-DSADCSAuthority
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

        Write-Verbose "Querying domain: $DomainName for Enterprise CA servers"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $configNC = "CN=Configuration,$domainDN"

        $ldapPath   = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        $ldapFilter = '(objectClass=pKIEnrollmentService)'
        $properties = @(
            'name'
            'distinguishedName'
            'dNSHostName'
            'cACertificateExpirationTime'
            'msPKI-Enrollment-Servers'
            'flags'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $queryResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($obj in $queryResults)
        {
            $caName     = [string]$obj['name'][0]
            $dnsHost    = if ($null -ne $obj['dnshostname'][0]) { [string]$obj['dnshostname'][0] } else { $null }
            $expiryRaw  = $obj['cacertificateexpirationtime'][0]
            $expiry     = if ($null -ne $expiryRaw) { [DateTime]::FromFileTime([long]$expiryRaw) } else { $null }
            $enrollSvrs = if ($null -ne $obj['mspki-enrollment-servers']) { @($obj['mspki-enrollment-servers']) } else { @() }
            $flags      = if ($null -ne $obj['flags'][0]) { [int]$obj['flags'][0] } else { 0 }

            # CA Type: 1 = Enterprise Root, 3 = Enterprise Subordinate
            $caType = switch ($flags)
            {
                1 { 'EnterpriseRoot' }
                3 { 'EnterpriseSubordinate' }
                default { "Unknown($flags)" }
            }

            # Check for web enrollment endpoints
            $hasWebEnrollment = $enrollSvrs.Count -gt 0
            $httpEndpoints    = @($enrollSvrs | Where-Object { $_ -match '^http://' })

            # RiskLevel: HTTP (non-HTTPS) enrollment endpoints expose NTLM authentication to relay
            # attacks (ESC8). A certificate nearing expiry disrupts authentication for all relying
            # parties but is not directly exploitable — rated High for operational impact.
            $isExpiringSoon = $null -ne $expiry -and ($expiry - (Get-Date)).TotalDays -le 30
            $caRiskLevel = if ($httpEndpoints.Count -gt 0) { 'Critical' }
                           elseif ($isExpiringSoon) { 'High' }
                           else { 'Informational' }

            [void]$results.Add(
                [PSCustomObject]@{
                    Name              = $caName
                    DistinguishedName = [string]$obj['distinguishedname'][0]
                    DNSHostName       = $dnsHost
                    CAType            = $caType
                    CertificateExpiry = $expiry
                    EnrollmentServers = $enrollSvrs
                    HasWebEnrollment  = $hasWebEnrollment
                    HTTPEndpoints     = $httpEndpoints
                    HTTPEndpointCount = $httpEndpoints.Count
                    RiskLevel         = $caRiskLevel
                }
            )
        }
    }

    End
    {
        $results.ToArray()
    }
}
