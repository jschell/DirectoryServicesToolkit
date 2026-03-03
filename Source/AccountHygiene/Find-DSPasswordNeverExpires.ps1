function Find-DSPasswordNeverExpires
{
<#
.SYNOPSIS
Finds accounts with the DONT_EXPIRE_PASSWORD flag set in userAccountControl.

.DESCRIPTION
Identifies user accounts with the DONT_EXPIRE_PASSWORD flag (userAccountControl
bit 0x10000 / 65536) set. Passwords that never expire accumulate age over time,
increasing the window for offline attacks on captured hashes.

Cross-referencing output with Find-DSKerberoastable results surfaces the
highest-risk overlap — service accounts with SPNs that also have non-expiring
passwords.

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeDisabled
When specified, disabled accounts with DONT_EXPIRE_PASSWORD are included.

.EXAMPLE
Find-DSPasswordNeverExpires -Domain 'contoso.com'

Returns all enabled accounts with non-expiring passwords.

.EXAMPLE
Find-DSPasswordNeverExpires -IncludeDisabled

Returns all accounts (enabled and disabled) with non-expiring passwords.

.NOTES
#### Name:    Find-DSPasswordNeverExpires
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
        [switch]$IncludeDisabled
    )

    Begin
    {
        throw [System.NotImplementedException]'Find-DSPasswordNeverExpires is not yet implemented'
    }

    Process {}

    End {}
}
