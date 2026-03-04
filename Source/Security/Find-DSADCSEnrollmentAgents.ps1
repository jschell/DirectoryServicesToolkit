function Find-DSADCSEnrollmentAgents
{
<#
.SYNOPSIS
Finds certificate templates granting enrollment agent rights (ESC3).

.DESCRIPTION
Identifies certificate templates that grant Certificate Request Agent (enrollment
agent) rights via the Certificate Request Agent EKU (OID 1.3.6.1.4.1.311.20.2.1).
Enrollment agents can request certificates on behalf of other users, enabling
impersonation attacks (ESC3).

Requires read access to the Configuration naming context.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Find-DSADCSEnrollmentAgents -Domain 'contoso.com'

Returns all certificate templates with the Certificate Request Agent EKU configured
in the contoso.com domain.

.EXAMPLE
Find-DSADCSEnrollmentAgents -Domain 'contoso.com' | Select-Object Name, RASignatureCount

Lists enrollment agent template names and whether additional authorized signatures
are required.

.NOTES
#### Name:    Find-DSADCSEnrollmentAgents
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

        Write-Verbose "Querying domain: $DomainName for enrollment agent templates"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $configNC = "CN=Configuration,$domainDN"

        $ldapPath   = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        $ldapFilter = '(&(objectClass=pKICertificateTemplate)(pkiExtendedKeyUsage=1.3.6.1.4.1.311.20.2.1))'
        $properties = @(
            'name'
            'distinguishedName'
            'pKIExtendedKeyUsage'
            'msPKI-RA-Signature'
            'msPKI-Enrollment-Flag'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $queryResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($obj in $queryResults)
        {
            [void]$results.Add(
                [PSCustomObject]@{
                    Name              = [string]$obj['name'][0]
                    DistinguishedName = [string]$obj['distinguishedname'][0]
                    EKUs              = if ($null -ne $obj['pkiextendedkeyusage']) { @($obj['pkiextendedkeyusage']) } else { @() }
                    RASignatureCount  = if ($null -ne $obj['mspki-ra-signature'][0]) { [int]$obj['mspki-ra-signature'][0] } else { 0 }
                    EnrollmentFlag    = if ($null -ne $obj['mspki-enrollment-flag'][0]) { [int]$obj['mspki-enrollment-flag'][0] } else { 0 }
                    RiskLevel         = 'High'
                    Finding           = "Template grants Certificate Request Agent (enrollment agent) rights — ESC3 candidate"
                }
            )
        }
    }

    End
    {
        $results.ToArray()
    }
}
