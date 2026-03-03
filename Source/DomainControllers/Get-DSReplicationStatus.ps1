function Get-DSReplicationStatus
{
<#
.SYNOPSIS
Returns Active Directory replication status across Domain Controllers.

.DESCRIPTION
Queries the replication metadata for all Domain Controllers in the domain
and returns per-DC, per-naming-context replication statistics including:

  - Last successful replication time
  - Last replication attempt time
  - Consecutive replication failures
  - Last replication result (Win32 error code, 0 = success)
  - Replication partner name

A non-zero LastReplicationResult or a high ConsecutiveFailures count
indicates a replication problem that should be investigated.

Requires read access to the domain partition. Reads from
CN=NTDS Settings objects and replication neighbor metadata.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER ShowFailuresOnly
When specified, returns only entries where the last replication result
was non-zero (i.e., replication has failed or is failing).

.EXAMPLE
Get-DSReplicationStatus -Domain 'contoso.com'

Returns full replication status for all DCs and naming contexts.

.EXAMPLE
Get-DSReplicationStatus -ShowFailuresOnly

Returns only replication links that are currently in a failed state.

.NOTES
#### Name:    Get-DSReplicationStatus
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
        [switch]$ShowFailuresOnly
    )

    Begin
    {
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)

        try
        {
            $DomainEntry = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $DomainName  = $DomainEntry.Name
            $dcNames     = @($DomainEntry.DomainControllers | ForEach-Object { $_.Name })
            $DomainEntry.Dispose()
        }
        catch
        {
            Write-Error "Cannot connect to domain '$Domain': $_"
            return
        }

        Write-Verbose "Querying replication status for domain: $DomainName ($($dcNames.Count) DC(s))"
    }

    Process
    {
        foreach ($dcName in $dcNames)
        {
            Write-Verbose "Querying replication neighbors for: $dcName"

            $dcContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('DirectoryServer', $dcName)

            try
            {
                $dcObj = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($dcContext)

                try
                {
                    $neighbors = $dcObj.GetReplicationNeighbors()

                    foreach ($neighbor in $neighbors)
                    {
                        $lastResult   = [int]$neighbor.LastSyncResult
                        $consFailures = [int]$neighbor.ConsecutiveFailureCount
                        $isFailing    = ($consFailures -gt 0 -or $lastResult -ne 0)

                        if ($ShowFailuresOnly -and -not $isFailing) { continue }

                        $msg = if ($lastResult -eq 0)
                        {
                            'Success'
                        }
                        else
                        {
                            try   { ([System.ComponentModel.Win32Exception]$lastResult).Message }
                            catch { "Win32 error $lastResult" }
                        }

                        [PSCustomObject]@{
                            DCName                = $dcName
                            Partner               = $neighbor.SourceServer
                            NamingContext         = $neighbor.PartitionName
                            LastAttempted         = $neighbor.LastAttemptedSync
                            LastSuccessful        = $neighbor.LastSuccessfulSync
                            ConsecutiveFailures   = $consFailures
                            LastSyncResult        = $lastResult
                            LastSyncResultMessage = $msg
                            IsFailing             = $isFailing
                        }
                    }
                }
                finally
                {
                    $dcObj.Dispose()
                }
            }
            catch
            {
                Write-Warning "Cannot connect to DC '$dcName': $_"
            }
        }
    }

    End {}
}
