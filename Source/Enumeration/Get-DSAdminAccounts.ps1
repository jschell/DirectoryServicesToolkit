function Get-DSAdminAccounts
{
<#
.SYNOPSIS
Enumerates all accounts in privileged Active Directory groups.

.DESCRIPTION
Returns members of the following built-in privileged groups with recursive
membership resolution:

  - Domain Admins
  - Enterprise Admins
  - Schema Admins
  - Administrators (built-in)
  - Protected Users

Recursive resolution uses the LDAP_MATCHING_RULE_IN_CHAIN OID
(1.2.840.113556.1.4.1941) to expand nested group membership in a single
query per group, surfacing all effective principals with elevated access.

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER Groups
One or more group names to enumerate. Defaults to the standard privileged
group set listed above.

.EXAMPLE
Get-DSAdminAccounts -Domain 'contoso.com'

Returns all members of privileged groups in the contoso.com domain.

.EXAMPLE
Get-DSAdminAccounts -Groups 'Domain Admins','Enterprise Admins'

Returns members of just Domain Admins and Enterprise Admins.

.NOTES
#### Name:    Get-DSAdminAccounts
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
        [string[]]$Groups = @(
            'Domain Admins'
            'Enterprise Admins'
            'Schema Admins'
            'Administrators'
            'Protected Users'
        )
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

        Write-Verbose "Querying domain: $DomainName for privileged group members"

        $ldapPath   = "LDAP://$DomainName"
        $properties = @(
            'distinguishedName'
            'sAMAccountName'
            'userAccountControl'
            'pwdLastSet'
            'lastLogonTimestamp'
            'memberOf'
        )

        # ── Resolve each group name to a DN ──────────────────────────────────

        $groupDnMap = @{}  # groupName → DN

        foreach ($groupName in $Groups)
        {
            $groupFilter = "(&(objectClass=group)(sAMAccountName=$groupName))"
            $groupResults = Invoke-DSDirectorySearch -LdapPath $ldapPath `
                -Filter $groupFilter -Properties @('distinguishedName')

            if ($groupResults.Count -gt 0)
            {
                $groupDnMap[$groupName] = [string]$groupResults[0]['distinguishedname'][0]
                Write-Verbose "Resolved group '$groupName' -> $($groupDnMap[$groupName])"
            }
            else
            {
                Write-Verbose "Group '$groupName' not found in domain '$DomainName' — skipping"
            }
        }

        # ── Accumulate results — keyed by DN for deduplication ───────────────

        # $accountMap[dn] = @{ obj = hashtable; groups = [List[string]] }
        $accountMap = [System.Collections.Generic.Dictionary[string, object]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    }

    Process
    {
        foreach ($groupName in $groupDnMap.Keys)
        {
            $groupDn     = $groupDnMap[$groupName]
            $memberFilter = "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$groupDn))"

            Write-Verbose "Querying transitive members of '$groupName'"

            $members = Invoke-DSDirectorySearch -LdapPath $ldapPath `
                -Filter $memberFilter -Properties $properties

            foreach ($obj in $members)
            {
                $dn = [string]$obj['distinguishedname'][0]

                if ($accountMap.ContainsKey($dn))
                {
                    # Already seen — append to group list
                    [void]$accountMap[$dn].Groups.Add($groupName)
                }
                else
                {
                    $entry = [PSCustomObject]@{
                        Object = $obj
                        Groups = [System.Collections.Generic.List[string]]::new()
                    }
                    [void]$entry.Groups.Add($groupName)
                    $accountMap[$dn] = $entry
                }
            }
        }
    }

    End
    {
        foreach ($dn in $accountMap.Keys)
        {
            $entry = $accountMap[$dn]
            $obj   = $entry.Object
            $uac   = [int]$obj['useraccountcontrol'][0]

            $pwdLastSetRaw = $obj['pwdlastset'][0]
            $passwordLastSet = if ($null -ne $pwdLastSetRaw -and [long]$pwdLastSetRaw -gt 0)
            {
                [DateTime]::FromFileTime([long]$pwdLastSetRaw)
            }
            else
            {
                $null
            }

            $lastLogonRaw = $obj['lastlogontimestamp'][0]
            $lastLogon = if ($null -ne $lastLogonRaw -and [long]$lastLogonRaw -gt 0)
            {
                [DateTime]::FromFileTime([long]$lastLogonRaw)
            }
            else
            {
                $null
            }

            [PSCustomObject]@{
                SamAccountName    = [string]$obj['samaccountname'][0]
                DistinguishedName = $dn
                Enabled           = -not [bool]($uac -band 2)
                PasswordLastSet   = $passwordLastSet
                LastLogon         = $lastLogon
                Groups            = @($entry.Groups)
            }
        }
    }
}
