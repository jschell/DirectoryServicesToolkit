function Find-DSKerberoastable
{
<#
.SYNOPSIS
Finds user accounts with SPNs set that are candidates for Kerberoasting.

.DESCRIPTION
Enumerates user accounts in Active Directory that have a Service Principal Name
(SPN) configured. Any domain user can request a Kerberos service ticket for
these accounts; the resulting ticket is encrypted with the account's password
hash and can be cracked offline (Kerberoasting).

Excludes krbtgt by default. Optionally excludes Managed Service Accounts
(MSAs) and Group Managed Service Accounts (gMSAs), which have randomly
rotated 120-character passwords and are not practically crackable.

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeDisabled
When specified, disabled accounts with SPNs are included in results.
Useful for complete assessment coverage.

.PARAMETER ExcludeManagedAccounts
When specified, Managed Service Accounts (objectClass msDS-ManagedServiceAccount
and msDS-GroupManagedServiceAccount) are excluded from results.

.EXAMPLE
Find-DSKerberoastable -Domain 'contoso.com'

Returns all enabled user accounts with SPNs, excluding krbtgt.

.EXAMPLE
Find-DSKerberoastable -Domain 'contoso.com' -IncludeDisabled -ExcludeManagedAccounts

Returns all accounts with SPNs including disabled ones, excluding MSAs/gMSAs.

.NOTES
#### Name:    Find-DSKerberoastable
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
        [Parameter(HelpMessage = 'DNS name of the target domain')]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter(HelpMessage = 'Include disabled accounts in results')]
        [switch]$IncludeDisabled,

        [Parameter(HelpMessage = 'Exclude MSA and gMSA accounts from results')]
        [switch]$ExcludeManagedAccounts
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

        Write-Verbose "Querying domain: $DomainName for Kerberoastable accounts"

        # Build LDAP filter dynamically from parameters
        $filterParts = @(
            '(objectClass=user)'
            '(servicePrincipalName=*)'
            '(!(cn=krbtgt))'
        )

        if (-not $IncludeDisabled)
        {
            $filterParts += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
        }

        if ($ExcludeManagedAccounts)
        {
            $filterParts += '(!(objectClass=msDS-GroupManagedServiceAccount))'
            $filterParts += '(!(objectClass=msDS-ManagedServiceAccount))'
        }

        $ldapFilter = '(&{0})' -f ($filterParts -join '')
        Write-Verbose "LDAP filter: $ldapFilter"

        $ldapPath   = "LDAP://$DomainName"
        $properties = @(
            'distinguishedName'
            'sAMAccountName'
            'servicePrincipalName'
            'userAccountControl'
            'pwdLastSet'
            'objectClass'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $queryResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        $now = Get-Date

        foreach ($obj in $queryResults)
        {
            $uac = [int]$obj['useraccountcontrol'][0]

            $pwdLastSetRaw = $obj['pwdlastset'][0]
            if ($null -ne $pwdLastSetRaw -and [long]$pwdLastSetRaw -gt 0)
            {
                $passwordLastSet = [DateTime]::FromFileTime([long]$pwdLastSetRaw)
                $passwordAgeDays = [int]($now - $passwordLastSet).TotalDays
            }
            else
            {
                $passwordLastSet = $null
                $passwordAgeDays = $null
            }

            $isManagedAccount = $obj['objectclass'] -contains 'msDS-GroupManagedServiceAccount' -or
                                $obj['objectclass'] -contains 'msDS-ManagedServiceAccount'

            # RiskLevel: managed accounts have auto-rotated passwords and are not practically crackable.
            # For non-managed accounts, risk scales with password age — older passwords are more
            # likely to be crackable with modern rulesets.
            $riskLevel = if ($isManagedAccount)
            {
                'Low'
            }
            elseif ($null -eq $passwordAgeDays)
            {
                'High'   # Password never set — unknown age, treat as elevated
            }
            elseif ($passwordAgeDays -ge 365)
            {
                'Critical'
            }
            elseif ($passwordAgeDays -ge 90)
            {
                'High'
            }
            else
            {
                'Medium'
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    SamAccountName    = [string]$obj['samaccountname'][0]
                    DistinguishedName = [string]$obj['distinguishedname'][0]
                    SPNs              = @($obj['serviceprincipalname'])
                    PasswordLastSet   = $passwordLastSet
                    PasswordAgeDays   = $passwordAgeDays
                    Enabled           = -not [bool]($uac -band 2)
                    IsManagedAccount  = [bool]$isManagedAccount
                    RiskLevel         = $riskLevel
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property PasswordAgeDays -Descending
    }
}
