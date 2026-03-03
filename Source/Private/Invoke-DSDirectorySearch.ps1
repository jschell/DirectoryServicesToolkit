function Invoke-DSDirectorySearch
{
<#
.SYNOPSIS
Internal helper — executes a paged LDAP search and returns results as plain hashtables.

.DESCRIPTION
Wraps System.DirectoryServices DirectorySearcher, executes a paged LDAP query, converts
each SearchResult to a plain [hashtable] keyed by lowercase property name, and returns all
results as an array. Disposes the searcher and result set on completion.

Private function — not exported. Wrapped here to enable unit-test mocking via InModuleScope.

.NOTES
#### Name:    Invoke-DSDirectorySearch
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-03::0.1.0
- Initial creation
#>

    [CmdletBinding()]
    [OutputType([hashtable[]])]
    Param
    (
        [Parameter(Mandatory, HelpMessage = 'LDAP path for the search root')]
        [ValidateNotNullOrEmpty()]
        [string]$LdapPath,

        [Parameter(Mandatory, HelpMessage = 'LDAP filter string')]
        [ValidateNotNullOrEmpty()]
        [string]$Filter,

        [Parameter(Mandatory, HelpMessage = 'Attributes to retrieve')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Properties,

        [Parameter(HelpMessage = 'Page size for paged search')]
        [ValidateRange(1, 1000)]
        [int]$PageSize = 1000,

        [Parameter(HelpMessage = 'Maximum results (0 = unlimited)')]
        [ValidateRange(0, 100000)]
        [int]$SizeLimit = 0
    )

    $searcher = [adsisearcher][adsi]$LdapPath
    $searcher.Filter   = $Filter
    $searcher.PageSize = $PageSize

    if ($SizeLimit -gt 0)
    {
        $searcher.SizeLimit = $SizeLimit
    }

    [void]$searcher.PropertiesToLoad.Clear()
    foreach ($prop in $Properties)
    {
        [void]$searcher.PropertiesToLoad.Add($prop)
    }

    $allResults  = New-Object System.Collections.ArrayList
    $queryResult = $null

    try
    {
        $queryResult = $searcher.FindAll()

        foreach ($result in $queryResult)
        {
            $propDict = @{}
            foreach ($key in $result.Properties.PropertyNames)
            {
                $propDict[$key] = @($result.Properties[$key])
            }
            [void]$allResults.Add($propDict)
        }
    }
    finally
    {
        if ($null -ne $queryResult) { $queryResult.Dispose() }
        $searcher.Dispose()
    }

    , [hashtable[]]$allResults
}
