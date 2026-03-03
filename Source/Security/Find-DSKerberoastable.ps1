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
- Initial creation — stub, pending implementation
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter()]
        [switch]$IncludeDisabled,

        [Parameter()]
        [switch]$ExcludeManagedAccounts
    )

    Begin
    {
        throw [System.NotImplementedException]'Find-DSKerberoastable is not yet implemented'
    }

    Process {}

    End {}
}
