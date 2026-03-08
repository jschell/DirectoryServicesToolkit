function Test-DSADCSContainerACL
{
<#
.SYNOPSIS
Enumerates ACLs on the PKI container hierarchy for ESC5 write-permission vulnerabilities.

.DESCRIPTION
Reads the DACL of the PKI object hierarchy in the Configuration naming context and
identifies non-privileged principals with write-equivalent rights. Write access to
these objects can allow an attacker to create or modify Enrollment Services objects,
NTAuthCertificates entries, or AIA/CDP containers — enabling PKI infrastructure abuse.

Objects checked (ESC5 scope):
  - CN=Public Key Services,CN=Services,CN=Configuration,...  (root PKI container)
  - CN=Certification Authorities,...                         (trusted root store)
  - CN=Enrollment Services,...                               (CA enrollment objects)
  - CN=NTAuthCertificates,...                                (enterprise trust store)
  - CN=AIA,...                                               (Authority Info Access)
  - CN=CDP,...                                               (CRL Distribution Points)
  - CN=OID,...                                               (certificate OID objects)

Dangerous rights checked:
  - GenericAll, GenericWrite, WriteProperty, WriteDacl, WriteOwner, CreateChild

Expected privileged principals are excluded by default (Administrators, Domain/Enterprise
Admins, Schema Admins, SYSTEM, ENTERPRISE DOMAIN CONTROLLERS, CREATOR OWNER).

Requires LDAP read access to the Configuration naming context and ability to read DACLs.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeSafeAces
When specified, returns all ACEs including those held by expected privileged principals.

.EXAMPLE
Test-DSADCSContainerACL -Domain 'contoso.com'

Returns non-privileged write ACEs on PKI container objects (ESC5 candidates).

.EXAMPLE
Test-DSADCSContainerACL | Where-Object { $_.IsVulnerable }

Returns only ACEs that represent ESC5 risk.

.NOTES
#### Name:    Test-DSADCSContainerACL
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-08::0.1.0
- Initial creation — ESC5 PKI container ACL check

NIST 800-53: SC-17, AC-3, AC-6
NIST 800-207: Identity pillar — certificate infrastructure integrity
CMMC Level 3: 3.13.10 (employ PKI/MFA), 3.1.2

.LINK
https://posts.specterops.io/certified-pre-owned-d95910965cd2
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(HelpMessage = 'DNS name of the target domain')]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter(HelpMessage = 'Include ACEs held by expected privileged principals')]
        [switch]$IncludeSafeAces
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

        Write-Verbose "Checking PKI container ACLs (ESC5) in domain: $DomainName"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $configNC = "CN=Configuration,$domainDN"
        $pkiRoot  = "CN=Public Key Services,CN=Services,$configNC"

        # All ESC5-relevant PKI containers
        $pkiContainers = @(
            @{ DN = $pkiRoot;                                                   FriendlyName = 'Public Key Services (root)' }
            @{ DN = "CN=Certification Authorities,$pkiRoot";                    FriendlyName = 'Certification Authorities' }
            @{ DN = "CN=Enrollment Services,$pkiRoot";                          FriendlyName = 'Enrollment Services' }
            @{ DN = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$configNC"; FriendlyName = 'NTAuthCertificates' }
            @{ DN = "CN=AIA,$pkiRoot";                                          FriendlyName = 'AIA Container' }
            @{ DN = "CN=CDP,$pkiRoot";                                          FriendlyName = 'CDP Container' }
            @{ DN = "CN=OID,CN=Public Key Services,CN=Services,$configNC";     FriendlyName = 'OID Container' }
        )

        $dangerousRights = @('GenericAll', 'GenericWrite', 'WriteProperty', 'WriteDacl', 'WriteOwner', 'CreateChild')

        $safePrincipals = @(
            'S-1-5-18'
            'S-1-5-9'
            'S-1-3-0'
            'NT AUTHORITY\SYSTEM'
            'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
            'BUILTIN\Administrators'
            'CREATOR OWNER'
        )

        $safeGroupPatterns = @(
            'Domain Admins'
            'Enterprise Admins'
            'Schema Admins'
            'Cert Publishers'
            'Administrators'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        foreach ($container in $pkiContainers)
        {
            $containerDN   = $container.DN
            $friendlyName  = $container.FriendlyName
            $ldapPath      = "LDAP://$containerDN"

            Write-Verbose "Reading ACL for: $friendlyName ($containerDN)"

            try
            {
                $aces = Get-DSObjectAcl -LdapPath $ldapPath
            }
            catch
            {
                Write-Verbose "Could not read ACL for '$containerDN': $_"
                continue
            }

            foreach ($ace in $aces)
            {
                if ($ace.AccessControlType -ne 'Allow') { continue }

                $rights            = $ace.ActiveDirectoryRights.ToString()
                $hasDangerousRight = $false
                $matchedRights     = @()

                foreach ($right in $dangerousRights)
                {
                    if ($rights -match $right) { $hasDangerousRight = $true; $matchedRights += $right }
                }

                if (-not $hasDangerousRight) { continue }

                $identity = $ace.IdentityReference
                $isSafe   = $false

                foreach ($safe in $safePrincipals)
                {
                    if ($identity -eq $safe) { $isSafe = $true; break }
                }

                if (-not $isSafe)
                {
                    foreach ($pattern in $safeGroupPatterns)
                    {
                        if ($identity -like "*$pattern*") { $isSafe = $true; break }
                    }
                }

                if ($isSafe -and -not $IncludeSafeAces) { continue }

                $isVulnerable = -not $isSafe

                $riskLevel = if ($isVulnerable)
                {
                    if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner' -or $matchedRights -contains 'CreateChild')
                    { 'Critical' }
                    else
                    { 'High' }
                }
                else
                {
                    'Informational'
                }

                [void]$results.Add(
                    [PSCustomObject]@{
                        ContainerName     = $friendlyName
                        ContainerDN       = $containerDN
                        IdentityReference = $identity
                        Rights            = $rights
                        MatchedRights     = $matchedRights
                        IsInherited       = $ace.IsInherited
                        IsPrivilegedOwner = $isSafe
                        IsVulnerable      = $isVulnerable
                        RiskLevel         = $riskLevel
                        Finding           = if ($isVulnerable) { "ESC5: '$identity' has $($matchedRights -join ', ') on '$friendlyName'" } else { $null }
                    }
                )
            }
        }
    }

    End
    {
        $results | Sort-Object -Property IsVulnerable -Descending
    }
}
