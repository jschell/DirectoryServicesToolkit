function Find-DSADCSTemplateACL
{
<#
.SYNOPSIS
Enumerates certificate template ACLs for ESC4 write-permission vulnerabilities.

.DESCRIPTION
Reads the DACL of every certificate template in the Configuration naming context and
identifies non-privileged principals that hold write-equivalent rights. Write access
to a template object allows an attacker to modify the template configuration into an
ESC1-equivalent condition (enrollee supplies SAN, no manager approval) and then
self-enroll, resulting in arbitrary principal impersonation.

ESC4 dangerous rights:
  - GenericAll         — full control of the template object
  - GenericWrite       — write any property
  - WriteProperty      — write one or more specific properties
  - WriteDacl          — replace the DACL (allows escalation to GenericAll)
  - WriteOwner         — change the object owner (allows escalation to WriteDacl)

The following principals are excluded as expected privileged owners:
  - BUILTIN\Administrators, NT AUTHORITY\SYSTEM, NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
  - Domain Admins, Enterprise Admins, Schema Admins
  - Cert Publishers (CA service accounts)
  - CREATOR OWNER

Requires read access to the Configuration naming context and the ability to read
object DACLs via LDAP.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeSafeAces
When specified, returns all ACEs including those held by expected privileged principals.
Useful for baselining or auditing complete ACL state. By default, only non-privileged
write-capable ACEs are returned.

.EXAMPLE
Find-DSADCSTemplateACL -Domain 'contoso.com'

Returns all certificate templates with non-privileged write ACEs (ESC4 candidates).

.EXAMPLE
Find-DSADCSTemplateACL -Domain 'contoso.com' | Where-Object { $_.IsVulnerable }

Returns templates assessed as vulnerable to ESC4 template takeover.

.EXAMPLE
Find-DSADCSTemplateACL | Where-Object { $_.Rights -like '*WriteDacl*' }

Returns any non-privileged principal that can replace the DACL on a template.

.NOTES
#### Name:    Find-DSADCSTemplateACL
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-07::0.1.0
- Initial creation — ESC4 template write-permission check

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

        Write-Verbose "Querying domain: $DomainName for certificate template ACLs (ESC4)"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $configNC = "CN=Configuration,$domainDN"

        $ldapPath   = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        $ldapFilter = '(objectClass=pKICertificateTemplate)'
        $properties = @(
            'name'
            'distinguishedName'
        )

        # Rights flags that indicate write-equivalent access
        $dangerousRights = @(
            'GenericAll'
            'GenericWrite'
            'WriteProperty'
            'WriteDacl'
            'WriteOwner'
        )

        # Well-known privileged principals — SID suffixes and display names
        $safePrincipals = @(
            'S-1-5-18'                      # NT AUTHORITY\SYSTEM
            'S-1-5-9'                       # NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
            'S-1-3-0'                       # CREATOR OWNER
            'NT AUTHORITY\SYSTEM'
            'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
            'BUILTIN\Administrators'
            'CREATOR OWNER'
        )

        # Group name patterns matched case-insensitively
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
        $templates = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($tmpl in $templates)
        {
            $templateName = [string]$tmpl['name'][0]
            $templateDN   = [string]$tmpl['distinguishedname'][0]
            $templatePath = "LDAP://$templateDN"

            Write-Verbose "Reading ACL for template: $templateName"

            $aces = Get-DSObjectAcl -LdapPath $templatePath

            foreach ($ace in $aces)
            {
                if ($ace.AccessControlType -ne 'Allow')
                {
                    continue
                }

                $rights = $ace.ActiveDirectoryRights.ToString()

                # Check if ACE contains any dangerous right
                $hasDangerousRight = $false
                $matchedRights = @()

                foreach ($right in $dangerousRights)
                {
                    if ($rights -match $right)
                    {
                        $hasDangerousRight = $true
                        $matchedRights += $right
                    }
                }

                if (-not $hasDangerousRight)
                {
                    continue
                }

                $identity = $ace.IdentityReference

                # Determine if this principal is a known safe/privileged identity
                $isSafe = $false

                foreach ($safe in $safePrincipals)
                {
                    if ($identity -eq $safe)
                    {
                        $isSafe = $true
                        break
                    }
                }

                if (-not $isSafe)
                {
                    foreach ($pattern in $safeGroupPatterns)
                    {
                        if ($identity -like "*$pattern*")
                        {
                            $isSafe = $true
                            break
                        }
                    }
                }

                if ($isSafe -and -not $IncludeSafeAces)
                {
                    continue
                }

                $isVulnerable = -not $isSafe

                $riskLevel = if ($isVulnerable)
                {
                    if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner')
                    {
                        'Critical'
                    }
                    else
                    {
                        'High'
                    }
                }
                else
                {
                    'Informational'
                }

                [void]$results.Add(
                    [PSCustomObject]@{
                        TemplateName      = $templateName
                        TemplateDN        = $templateDN
                        IdentityReference = $identity
                        Rights            = $rights
                        MatchedRights     = $matchedRights
                        ObjectType        = $ace.ObjectType
                        IsInherited       = $ace.IsInherited
                        IsPrivilegedOwner = $isSafe
                        IsVulnerable      = $isVulnerable
                        RiskLevel         = $riskLevel
                        Finding           = if ($isVulnerable) { "ESC4: '$identity' has write access ($($matchedRights -join ', ')) on template '$templateName'" } else { $null }
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
