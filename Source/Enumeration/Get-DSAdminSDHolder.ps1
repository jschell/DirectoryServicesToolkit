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
        [switch]$IncludeExpected
    )

    Begin
    {
        throw [System.NotImplementedException]'Get-DSAdminSDHolder is not yet implemented'
    }

    Process {}

    End {}
}
