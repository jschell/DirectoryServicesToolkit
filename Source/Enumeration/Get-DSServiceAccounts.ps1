function Get-DSServiceAccounts
{
<#
.SYNOPSIS
Finds service accounts in Active Directory by common indicators.

.DESCRIPTION
Identifies accounts that are likely service accounts using multiple indicators:

  - Accounts with one or more Service Principal Names (SPNs) configured
  - Accounts in OUs whose distinguished name contains common service
    account OU keywords (ServiceAccounts, SvcAccts, Service, SA_, _svc)
  - Accounts whose description attribute contains common service account
    indicators (svc, service, scheduled, task, app)

Results include the account's SPN list, last password set date, whether
the password is set to never expire, and whether the account is enabled.
The DetectedBy property lists which indicator(s) triggered the match.

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER SearchBase
The distinguished name of the OU or container to limit the search to.

.EXAMPLE
Get-DSServiceAccounts -Domain 'contoso.com'

Returns all likely service accounts in the domain.

.EXAMPLE
Get-DSServiceAccounts -SearchBase 'OU=ServiceAccounts,DC=contoso,DC=com'

Returns service accounts scoped to the ServiceAccounts OU.

.NOTES
#### Name:    Get-DSServiceAccounts
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
        [string]$SearchBase
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

        Write-Verbose "Querying domain: $DomainName for service accounts"

        $ldapPath = if ($SearchBase)
        {
            "LDAP://$SearchBase"
        }
        else
        {
            "LDAP://$DomainName"
        }

        $properties = @(
            'distinguishedName'
            'sAMAccountName'
            'servicePrincipalName'
            'description'
            'userAccountControl'
            'pwdLastSet'
            'memberOf'
        )

        # OU keyword patterns for post-query DN matching
        $ouKeywords = @('ServiceAccount', 'SvcAcct', 'Service', 'SA_', '_svc')

        # Accumulate results keyed by DN to deduplicate across queries
        # Value: [hashtable]@{ Object = ...; DetectedBy = [List[string]] }
        $accountMap = [System.Collections.Generic.Dictionary[string, object]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    }

    Process
    {
        # ── Query 1: SPN-based ────────────────────────────────────────────────

        $spnFilter = '(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt)))'
        Write-Verbose "SPN query: $spnFilter"

        $spnResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $spnFilter -Properties $properties

        foreach ($obj in $spnResults)
        {
            $dn = [string]$obj['distinguishedname'][0]
            if (-not $accountMap.ContainsKey($dn))
            {
                $accountMap[$dn] = [PSCustomObject]@{
                    Object     = $obj
                    DetectedBy = [System.Collections.Generic.List[string]]::new()
                }
            }
            if (-not $accountMap[$dn].DetectedBy.Contains('SPN'))
            {
                [void]$accountMap[$dn].DetectedBy.Add('SPN')
            }
        }

        # ── Query 2: Description-based ────────────────────────────────────────

        $descFilter = '(&(objectClass=user)(|(description=*svc*)(description=*service*)(description=*scheduled*)(description=*task*)(description=*app*)))'
        Write-Verbose "Description query: $descFilter"

        $descResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $descFilter -Properties $properties

        foreach ($obj in $descResults)
        {
            $dn = [string]$obj['distinguishedname'][0]
            if (-not $accountMap.ContainsKey($dn))
            {
                $accountMap[$dn] = [PSCustomObject]@{
                    Object     = $obj
                    DetectedBy = [System.Collections.Generic.List[string]]::new()
                }
            }
            if (-not $accountMap[$dn].DetectedBy.Contains('Description'))
            {
                [void]$accountMap[$dn].DetectedBy.Add('Description')
            }
        }

        # ── Post-query: OU-pattern matching ───────────────────────────────────

        foreach ($dn in $accountMap.Keys)
        {
            foreach ($keyword in $ouKeywords)
            {
                if ($dn -match [regex]::Escape($keyword))
                {
                    if (-not $accountMap[$dn].DetectedBy.Contains('OU'))
                    {
                        [void]$accountMap[$dn].DetectedBy.Add('OU')
                    }
                    break
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

            $descRaw = $obj['description']
            $description = if ($descRaw -and $descRaw.Count -gt 0) { [string]$descRaw[0] } else { $null }

            [PSCustomObject]@{
                SamAccountName       = [string]$obj['samaccountname'][0]
                DistinguishedName    = $dn
                SPNs                 = @($obj['serviceprincipalname'])
                Description          = $description
                Enabled              = -not [bool]($uac -band 2)
                PasswordNeverExpires = [bool]($uac -band 65536)
                PasswordLastSet      = $passwordLastSet
                DetectedBy           = @($entry.DetectedBy)
            }
        }
    }
}
