function Find-DSADCSTemplate
{
<#
.SYNOPSIS
Enumerates AD CS certificate templates and evaluates them for ESC vulnerability conditions.

.DESCRIPTION
Queries the Certificate Templates container in the Configuration naming context and
evaluates each template against ESC1, ESC2, and ESC3 vulnerability conditions as
described in Certified Pre-Owned (SpecterOps).

ESC1: Enrollee supplies subject SAN allowing arbitrary principal impersonation.
ESC2: Any Purpose EKU enables template for any authentication use.
ESC3-Condition: No authorized signatures required for issuance.

Manager approval (CT_FLAG_PEND_ALL_REQUESTS) is treated as a mitigating control;
templates with manager approval required are marked IsVulnerable = $false even
when ESC flags are present.

Requires read access to the Configuration naming context.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Find-DSADCSTemplate -Domain 'contoso.com'

Returns all certificate templates with ESC flag analysis for the contoso.com domain.

.EXAMPLE
Find-DSADCSTemplate -Domain 'contoso.com' | Where-Object { $_.IsVulnerable }

Returns only templates assessed as exploitable (ESC flags set and no manager approval).

.NOTES
#### Name:    Find-DSADCSTemplate
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

        Write-Verbose "Querying domain: $DomainName for AD CS certificate templates"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $configNC = "CN=Configuration,$domainDN"

        $ldapPath   = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        $ldapFilter = '(objectClass=pKICertificateTemplate)'
        $properties = @(
            'name'
            'distinguishedName'
            'msPKI-Certificate-Name-Flag'
            'msPKI-Enrollment-Flag'
            'msPKI-RA-Signature'
            'pKIExtendedKeyUsage'
            'msPKI-Certificate-Application-Policy'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $queryResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($obj in $queryResults)
        {
            $nameFlag    = if ($null -ne $obj['mspki-certificate-name-flag'][0]) { [int]$obj['mspki-certificate-name-flag'][0] } else { 0 }
            $enrollFlag  = if ($null -ne $obj['mspki-enrollment-flag'][0]) { [int]$obj['mspki-enrollment-flag'][0] } else { 0 }
            $raSignature = if ($null -ne $obj['mspki-ra-signature'][0]) { [int]$obj['mspki-ra-signature'][0] } else { 1 }
            $ekus        = if ($null -ne $obj['pkiextendedkeyusage']) { @($obj['pkiextendedkeyusage']) } else { @() }
            $appPolicies = if ($null -ne $obj['mspki-certificate-application-policy']) { @($obj['mspki-certificate-application-policy']) } else { @() }

            # ESC1: Enrollee can supply subject
            $isESC1 = [bool]($nameFlag -band 0x1)

            # ESC2: Any Purpose EKU or empty EKU
            $isESC2 = ($ekus.Count -eq 0) -or ($ekus -contains '2.5.29.37.0') -or ($appPolicies -contains '2.5.29.37.0')

            # ESC3: No authorized signatures required
            $isESC3Condition = ($raSignature -eq 0)

            # Manager approval not required (no pending)
            $noManagerApproval = -not [bool]($enrollFlag -band 0x2)

            $escFlags = @()
            if ($isESC1) { $escFlags += 'ESC1' }
            if ($isESC2) { $escFlags += 'ESC2' }
            if ($isESC3Condition) { $escFlags += 'ESC3-Condition' }

            $isVulnerable = ($escFlags.Count -gt 0) -and $noManagerApproval

            # RiskLevel: driven by which ESC conditions are present and whether manager approval
            # mitigates them. ESC1 (enrollee-supplied SAN) allows immediate arbitrary principal
            # impersonation — Critical when exploitable. ESC2 (Any Purpose EKU) is nearly as
            # severe. ESC3-Condition alone (no RA signature) is a prerequisite, not a standalone
            # exploit, so it rates Medium. Manager approval removes exploitability entirely.
            $templateRiskLevel = if (-not $isVulnerable)
            {
                'Informational'
            }
            elseif ($isESC1)
            {
                'Critical'
            }
            elseif ($isESC2)
            {
                'High'
            }
            else
            {
                'Medium'
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    Name                    = [string]$obj['name'][0]
                    DistinguishedName       = [string]$obj['distinguishedname'][0]
                    ESCFlags                = $escFlags
                    IsVulnerable            = $isVulnerable
                    EnrolleeSuppliesSubject = $isESC1
                    AnyPurposeEKU           = $isESC2
                    NoRASignatureRequired   = $isESC3Condition
                    NoManagerApproval       = $noManagerApproval
                    EKUs                    = $ekus
                    NameFlag                = $nameFlag
                    EnrollmentFlag          = $enrollFlag
                    RASignatureCount        = $raSignature
                    RiskLevel               = $templateRiskLevel
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property IsVulnerable -Descending
    }
}
