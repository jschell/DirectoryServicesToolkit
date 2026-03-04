function Get-DSDomainControllerNames
{
<#
.SYNOPSIS
Internal helper — returns the list of Domain Controller hostnames for a domain.

.NOTES
This private function wraps [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain()
so that callers can be mocked in unit tests without requiring a live domain connection.
#>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param
    (
        [Parameter(Mandatory)]
        [string]$Domain
    )

    $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
    $DomainEntry   = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
    [string[]]$Names = @($DomainEntry.DomainControllers | ForEach-Object { $_.Name })
    $DomainEntry.Dispose()
    return $Names
}
