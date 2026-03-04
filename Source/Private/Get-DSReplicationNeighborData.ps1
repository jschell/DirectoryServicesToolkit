function Get-DSReplicationNeighborData
{
<#
.SYNOPSIS
Internal helper — returns replication neighbor objects for a Domain Controller.

.NOTES
This private function wraps [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController()
so that callers can be mocked in unit tests without requiring a live domain connection.
#>
    [CmdletBinding()]
    [OutputType([object[]])]
    Param
    (
        [Parameter(Mandatory)]
        [string]$DcName
    )

    $dcContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('DirectoryServer', $DcName)
    $dcObj     = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($dcContext)
    try
    {
        return @($dcObj.GetReplicationNeighbors())
    }
    finally
    {
        $dcObj.Dispose()
    }
}
