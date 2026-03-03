function Get-DSObjectAcl
{
<#
.SYNOPSIS
Internal helper — reads the DACL of an AD object and returns typed ACE records.

.DESCRIPTION
Binds to the specified LDAP DN via DirectoryEntry, reads the ObjectSecurity.Access
DACL, and returns each ACE as a flat PSCustomObject. Only Allow-type ACEs are
returned (Deny ACEs are surfaced separately if needed).

Private function — not exported. Wrapped here to enable unit-test mocking via InModuleScope.

.NOTES
#### Name:    Get-DSObjectAcl
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-03::0.1.0
- Initial creation
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param
    (
        [Parameter(Mandatory, HelpMessage = 'Full LDAP path to the object, e.g. LDAP://CN=...')]
        [ValidateNotNullOrEmpty()]
        [string]$LdapPath
    )

    $entry  = $null
    $aceList = New-Object System.Collections.ArrayList

    try
    {
        $entry = [adsi]$LdapPath
        $acl   = $entry.ObjectSecurity

        if ($null -eq $acl)
        {
            Write-Verbose "No ObjectSecurity on: $LdapPath"
            return , [PSCustomObject[]]$aceList
        }

        foreach ($ace in $acl.Access)
        {
            [void]$aceList.Add(
                [PSCustomObject]@{
                    IdentityReference    = $ace.IdentityReference.Value
                    ActiveDirectoryRights = $ace.ActiveDirectoryRights
                    AccessControlType    = $ace.AccessControlType.ToString()
                    ObjectType           = $ace.ObjectType
                    InheritanceType      = $ace.InheritanceType
                    IsInherited          = $ace.IsInherited
                }
            )
        }
    }
    catch
    {
        Write-Verbose "Could not read ACL for '$LdapPath': $_"
    }
    finally
    {
        if ($null -ne $entry) { $entry.Dispose() }
    }

    , [PSCustomObject[]]$aceList
}
