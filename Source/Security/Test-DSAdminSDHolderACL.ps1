function Test-DSAdminSDHolderACL
{
<#
.SYNOPSIS
Enumerates non-privileged ACEs on the AdminSDHolder object.

.DESCRIPTION
Reads the DACL of CN=AdminSDHolder,CN=System,<domainDN> and identifies non-privileged
principals that hold write-equivalent or full-control rights.

The SDProp process (runs every 60 minutes by default) copies the AdminSDHolder DACL
onto all protected accounts and groups (members of Administrators, Domain Admins,
Schema Admins, Enterprise Admins, etc.). A non-privileged principal with write access
to AdminSDHolder will have their ACE propagated to every protected object, providing
a persistent backdoor that survives most administrative cleanup.

Dangerous rights checked:
  - GenericAll         — full control (propagates to all protected objects)
  - GenericWrite       — write any property
  - WriteProperty      — write specific properties
  - WriteDacl          — replace the DACL
  - WriteOwner         — change the owner
  - ExtendedRight      — extended rights (e.g., Reset Password)

Expected privileged principals (excluded by default):
  - BUILTIN\Administrators, NT AUTHORITY\SYSTEM, NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
  - Domain Admins, Enterprise Admins, Schema Admins
  - CREATOR OWNER

Requires LDAP read access to the System container and ability to read object DACLs.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeSafeAces
When specified, returns all ACEs including those held by expected privileged principals.

.EXAMPLE
Test-DSAdminSDHolderACL -Domain 'contoso.com'

Returns non-privileged ACEs on the AdminSDHolder object.

.EXAMPLE
Test-DSAdminSDHolderACL | Where-Object { $_.IsVulnerable }

Returns only ACEs that represent a persistence risk.

.NOTES
#### Name:    Test-DSAdminSDHolderACL
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-08::0.1.0
- Initial creation — AdminSDHolder ACL persistence check

NIST 800-53: AC-3, AC-6, AC-6(1), IA-4
NIST 800-207: Identity pillar — privileged identity management
CMMC Level 3: 3.1.6 (use non-privileged accounts), 3.1.2

.LINK
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
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

        Write-Verbose "Querying AdminSDHolder ACL in domain: $DomainName"

        $domainDN       = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $adminSdHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
        $ldapPath       = "LDAP://$adminSdHolderDN"

        $dangerousRights = @(
            'GenericAll'
            'GenericWrite'
            'WriteProperty'
            'WriteDacl'
            'WriteOwner'
            'ExtendedRight'
        )

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
            'Administrators'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        Write-Verbose "Reading ACL for: $adminSdHolderDN"

        $aces = Get-DSObjectAcl -LdapPath $ldapPath

        foreach ($ace in $aces)
        {
            if ($ace.AccessControlType -ne 'Allow') { continue }

            $rights = $ace.ActiveDirectoryRights.ToString()

            $hasDangerousRight = $false
            $matchedRights     = @()

            foreach ($right in $dangerousRights)
            {
                if ($rights -match $right)
                {
                    $hasDangerousRight = $true
                    $matchedRights    += $right
                }
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
                if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner')
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
                    AdminSDHolderDN   = $adminSdHolderDN
                    IdentityReference = $identity
                    Rights            = $rights
                    MatchedRights     = $matchedRights
                    ObjectType        = $ace.ObjectType
                    IsInherited       = $ace.IsInherited
                    IsPrivilegedOwner = $isSafe
                    IsVulnerable      = $isVulnerable
                    RiskLevel         = $riskLevel
                    Finding           = if ($isVulnerable) { "AdminSDHolder backdoor: '$identity' has $($matchedRights -join ', ') — will propagate to all protected objects via SDProp" } else { $null }
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property IsVulnerable -Descending
    }
}
