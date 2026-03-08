function Find-DSGPOPermissions
{
<#
.SYNOPSIS
Enumerates Group Policy Object ACLs for non-privileged write-permission vulnerabilities.

.DESCRIPTION
Reads the DACL of every GPO in the domain and identifies non-privileged principals
that hold write-equivalent rights. An attacker with write access to a GPO linked to
computers or users can deploy malicious settings, scripts, or software.

Dangerous rights checked:
  - GenericAll         — full control of the GPO object
  - GenericWrite       — write any property
  - WriteProperty      — write one or more specific properties
  - WriteDacl          — replace the DACL (allows escalation to GenericAll)
  - WriteOwner         — change the object owner (allows escalation to WriteDacl)
  - CreateChild        — create child objects

The following principals are excluded as expected privileged owners:
  - BUILTIN\Administrators, NT AUTHORITY\SYSTEM, NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
  - Domain Admins, Enterprise Admins, Schema Admins, Group Policy Creator Owners
  - CREATOR OWNER

GPO metadata (DisplayName, linked OUs) is read from the domain LDAP tree.

Requires read access to the domain naming context and the ability to read object DACLs.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeSafeAces
When specified, returns all ACEs including those held by expected privileged principals.

.EXAMPLE
Find-DSGPOPermissions -Domain 'contoso.com'

Returns all GPOs with non-privileged write ACEs.

.EXAMPLE
Find-DSGPOPermissions | Where-Object { $_.IsVulnerable }

Returns only GPOs where a non-privileged principal has write access.

.NOTES
#### Name:    Find-DSGPOPermissions
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-08::0.1.0
- Initial creation — GPO write-permission ACL enumeration

NIST 800-53: AC-3, CM-6, CM-9, SI-7
NIST 800-207: Policy Engine pillar — policy enforcement integrity
CMMC Level 3: 3.4.2 (establish and maintain baseline configurations), 3.1.1

.LINK
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/62d1a4eb-c1b4-4fe9-99ec-7c5d8e9de9df
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

        Write-Verbose "Querying domain: $DomainName for GPO ACLs"

        $domainDN   = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $gpoCN      = "CN=Policies,CN=System,$domainDN"
        $ldapPath   = "LDAP://$gpoCN"
        $ldapFilter = '(objectClass=groupPolicyContainer)'
        $properties = @('name', 'displayName', 'distinguishedName', 'gPCFileSysPath')

        $dangerousRights = @(
            'GenericAll'
            'GenericWrite'
            'WriteProperty'
            'WriteDacl'
            'WriteOwner'
            'CreateChild'
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
            'Group Policy Creator Owners'
            'Administrators'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $gpos = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($gpo in $gpos)
        {
            $gpoName        = if ($gpo['displayname']) { [string]$gpo['displayname'][0] } else { [string]$gpo['name'][0] }
            $gpoGuid        = [string]$gpo['name'][0]
            $gpoDN          = [string]$gpo['distinguishedname'][0]
            $gpoSysvolPath  = if ($gpo['gpCFileSysPath']) { [string]$gpo['gpCFileSysPath'][0] } else { $null }

            Write-Verbose "Reading ACL for GPO: $gpoName ($gpoGuid)"

            $aces = Get-DSObjectAcl -LdapPath "LDAP://$gpoDN"

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
                        GPOName           = $gpoName
                        GPOGUID           = $gpoGuid
                        GPODN             = $gpoDN
                        GPOSysvolPath     = $gpoSysvolPath
                        IdentityReference = $identity
                        Rights            = $rights
                        MatchedRights     = $matchedRights
                        IsInherited       = $ace.IsInherited
                        IsPrivilegedOwner = $isSafe
                        IsVulnerable      = $isVulnerable
                        RiskLevel         = $riskLevel
                        Finding           = if ($isVulnerable) { "GPO write: '$identity' has $($matchedRights -join ', ') on GPO '$gpoName'" } else { $null }
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
