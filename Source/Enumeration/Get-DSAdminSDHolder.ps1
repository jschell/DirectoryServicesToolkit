function Get-DSAdminSDHolder
{
<#
.SYNOPSIS
Returns all objects where AdminCount is set to 1.

.DESCRIPTION
The SDProp process sets AdminCount=1 on members of protected groups (Domain
Admins, Enterprise Admins, etc.) and resets their DACL to match the
AdminSDHolder container every 60 minutes.

When an account is removed from all protected groups, AdminCount is NOT
automatically cleared. These "tombstoned" accounts retain a restricted DACL
and will not inherit future changes to parent OU ACLs, which can create ACL
abuse paths or administrative blind spots.

This function returns all objects with AdminCount=1 and flags those that are
not currently members of any known protected group — indicating the value was
left behind and should be reviewed.

Protected groups evaluated for cross-reference:
  Domain Admins, Enterprise Admins, Schema Admins, Administrators,
  Protected Users, Backup Operators, Account Operators, Server Operators,
  Print Operators, Group Policy Creator Owners, Replicator, krbtgt

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeExpected
When specified, accounts that are current members of protected groups are
included in results alongside the unexpected ones.

.EXAMPLE
Get-DSAdminSDHolder -Domain 'contoso.com'

Returns objects with AdminCount=1 that are not current members of protected groups.

.EXAMPLE
Get-DSAdminSDHolder -IncludeExpected

Returns all objects with AdminCount=1, including current protected group members.

.NOTES
#### Name:    Get-DSAdminSDHolder
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-03::0.1.0
- Initial creation
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter()]
        [switch]$IncludeExpected
    )

    Begin
    {
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)

        try
        {
            $DomainEntry = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $DomainName  = $DomainEntry.Name
            $DomainEntry.Dispose()
        }
        catch
        {
            Write-Error "Cannot connect to domain '$Domain': $_"
            return
        }

        Write-Verbose "Querying domain: $DomainName for AdminSDHolder residuals"

        $ldapPath       = "LDAP://$DomainName"
        $userProperties = @('distinguishedName', 'sAMAccountName', 'userAccountControl', 'objectClass', 'adminCount')

        # ── All protected groups for cross-reference ─────────────────────────

        $protectedGroupNames = @(
            'Domain Admins'
            'Enterprise Admins'
            'Schema Admins'
            'Administrators'
            'Protected Users'
            'Backup Operators'
            'Account Operators'
            'Server Operators'
            'Print Operators'
            'Group Policy Creator Owners'
            'Replicator'
            'krbtgt'
        )

        # ── Resolve group names to DNs ────────────────────────────────────────

        $groupDns = [System.Collections.Generic.List[string]]::new()

        foreach ($groupName in $protectedGroupNames)
        {
            $groupFilter  = "(&(objectClass=group)(sAMAccountName=$groupName))"
            $groupResults = Invoke-DSDirectorySearch -LdapPath $ldapPath `
                -Filter $groupFilter -Properties @('distinguishedName')

            if ($groupResults.Count -gt 0)
            {
                [void]$groupDns.Add([string]$groupResults[0]['distinguishedname'][0])
            }
            else
            {
                # krbtgt is a user object; also try CN=krbtgt lookup
                $krbtgtFilter  = "(&(objectClass=user)(sAMAccountName=$groupName))"
                $krbtgtResults = Invoke-DSDirectorySearch -LdapPath $ldapPath `
                    -Filter $krbtgtFilter -Properties @('distinguishedName')
                if ($krbtgtResults.Count -gt 0)
                {
                    [void]$groupDns.Add([string]$krbtgtResults[0]['distinguishedname'][0])
                }
                else
                {
                    Write-Verbose "Protected group '$groupName' not found — skipping"
                }
            }
        }

        Write-Verbose "Resolved $($groupDns.Count) protected group DNs"

        # ── Build current protected member set (DNs) ─────────────────────────

        $currentProtectedMembers = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )

        foreach ($groupDn in $groupDns)
        {
            $memberFilter = "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$groupDn))"
            $members = Invoke-DSDirectorySearch -LdapPath $ldapPath `
                -Filter $memberFilter -Properties @('distinguishedName')

            foreach ($m in $members)
            {
                [void]$currentProtectedMembers.Add([string]$m['distinguishedname'][0])
            }
        }

        Write-Verbose "Current protected member count: $($currentProtectedMembers.Count)"
    }

    Process
    {
        # ── Query adminCount=1 on user objects ────────────────────────────────

        $adminCountFilter = '(&(objectCategory=person)(adminCount=1))'
        $adminObjects = Invoke-DSDirectorySearch -LdapPath $ldapPath `
            -Filter $adminCountFilter -Properties $userProperties

        # ── Query adminCount=1 on computer objects ────────────────────────────

        $compFilter = '(&(objectCategory=computer)(adminCount=1))'
        $compObjects = Invoke-DSDirectorySearch -LdapPath $ldapPath `
            -Filter $compFilter -Properties $userProperties

        $allAdminCountObjects = @($adminObjects) + @($compObjects)

        foreach ($obj in $allAdminCountObjects)
        {
            $dn         = [string]$obj['distinguishedname'][0]
            $isCurrent  = $currentProtectedMembers.Contains($dn)

            if (-not $IncludeExpected -and $isCurrent)
            {
                continue
            }

            $uac        = [int]$obj['useraccountcontrol'][0]
            $objClasses = @($obj['objectclass'])
            $objClass   = if ($objClasses -contains 'computer') { 'computer' }
                          elseif ($objClasses -contains 'user') { 'user' }
                          else { [string]$objClasses[-1] }

            [PSCustomObject]@{
                SamAccountName            = [string]$obj['samaccountname'][0]
                DistinguishedName         = $dn
                ObjectClass               = $objClass
                Enabled                   = -not [bool]($uac -band 2)
                AdminCount                = 1
                IsCurrentProtectedMember  = $isCurrent
            }
        }
    }

    End {}
}
