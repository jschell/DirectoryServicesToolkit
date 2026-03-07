function Find-DSStalePrivilegedAccounts
{
<#
.SYNOPSIS
Identifies disabled accounts that retain membership in Tier 0 privileged groups.

.DESCRIPTION
Enumerates user accounts that are disabled (userAccountControl bit 2 set) while
remaining transitive members of the specified privileged groups. Disabled accounts
retaining Domain Admin or Enterprise Admin membership are a common offboarding gap
that can be exploited if the account is re-enabled or its Kerberos state manipulated.

Membership resolution uses the LDAP_MATCHING_RULE_IN_CHAIN OID
(1.2.840.113556.1.4.1941) to expand nested group membership in a single query per
group, surfacing all effective principals including indirect members through nested
groups.

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER Groups
One or more group names to enumerate. Defaults to the standard Tier 0 set:
  Domain Admins, Enterprise Admins, Schema Admins, Administrators.

.EXAMPLE
Find-DSStalePrivilegedAccounts -Domain 'contoso.com'

Returns all disabled accounts that are transitive members of Tier 0 groups in
the contoso.com domain.

.EXAMPLE
Find-DSStalePrivilegedAccounts -Groups 'Domain Admins','Enterprise Admins'

Returns disabled accounts in just Domain Admins and Enterprise Admins.

.EXAMPLE
Find-DSStalePrivilegedAccounts | Where-Object { $_.Groups -contains 'Enterprise Admins' }

Returns disabled accounts that are members of Enterprise Admins specifically.

.NOTES
#### Name:    Find-DSStalePrivilegedAccounts
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-07::0.1.0
- Initial creation — disabled accounts in Tier 0 privileged groups

#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(HelpMessage = 'DNS name of the target domain')]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter(HelpMessage = 'One or more privileged group names to search')]
        [string[]]$Groups = @(
            'Domain Admins'
            'Enterprise Admins'
            'Schema Admins'
            'Administrators'
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

        Write-Verbose "Querying domain: $DomainName for disabled accounts in privileged groups"

        $ldapPath   = "LDAP://$DomainName"
        $properties = @(
            'distinguishedName'
            'sAMAccountName'
            'userAccountControl'
            'pwdLastSet'
            'lastLogonTimestamp'
            'whenChanged'
        )

        # Resolve each group name to a DN
        $groupDnMap = @{}

        foreach ($groupName in $Groups)
        {
            $groupFilter  = "(&(objectClass=group)(sAMAccountName=$groupName))"
            $groupResults = @(Invoke-DSDirectorySearch -LdapPath $ldapPath `
                -Filter $groupFilter -Properties @('distinguishedName'))

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

        # Accumulate results keyed by DN for deduplication across group queries
        $accountMap = [System.Collections.Generic.Dictionary[string, object]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    }

    Process
    {
        foreach ($groupName in $groupDnMap.Keys)
        {
            $groupDn = $groupDnMap[$groupName]

            # Filter for disabled users (UAC bit 2 = 0x2) that are transitive members
            $memberFilter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(memberOf:1.2.840.113556.1.4.1941:=$groupDn))"

            Write-Verbose "Querying disabled transitive members of '$groupName'"

            $members = Invoke-DSDirectorySearch -LdapPath $ldapPath `
                -Filter $memberFilter -Properties $properties

            foreach ($obj in $members)
            {
                $dn = [string]$obj['distinguishedname'][0]

                if ($accountMap.ContainsKey($dn))
                {
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

            $whenChangedRaw = $obj['whenchanged'][0]
            $whenChanged = if ($null -ne $whenChangedRaw)
            {
                try { [DateTime]$whenChangedRaw } catch { $null }
            }
            else
            {
                $null
            }

            $groupList = @($entry.Groups)

            # Tier 0 membership escalates risk level
            $isTier0 = ($groupList -contains 'Domain Admins') -or
                       ($groupList -contains 'Enterprise Admins') -or
                       ($groupList -contains 'Schema Admins')

            $riskLevel = if ($isTier0) { 'Critical' } else { 'High' }

            [PSCustomObject]@{
                SamAccountName    = [string]$obj['samaccountname'][0]
                DistinguishedName = $dn
                Enabled           = $false
                PasswordLastSet   = $passwordLastSet
                LastLogon         = $lastLogon
                WhenChanged       = $whenChanged
                Groups            = $groupList
                RiskLevel         = $riskLevel
                Finding           = "Stale account disabled but retains membership in: $($groupList -join ', ')"
            }
        }
    }
}
