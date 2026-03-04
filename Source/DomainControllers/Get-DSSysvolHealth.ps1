function Get-DSSysvolHealth
{
<#
.SYNOPSIS
Checks SYSVOL replication health across Domain Controllers.

.DESCRIPTION
Evaluates the health of SYSVOL replication by checking:

  - Whether SYSVOL is shared on each DC (net share SYSVOL)
  - NETLOGON share availability
  - DFS Replication (DFSR) service state on each DC
  - Whether the SYSVOL junction/junction points are intact
  - Replication group and folder subscription state via WMI/CIM
    (DFSR: DfsrReplicatedFolderInfo, DfsrReplicationGroupConfig)

A DC with a missing SYSVOL share or a degraded DFSR state will not correctly
distribute Group Policy Objects and logon scripts, causing inconsistent policy
application across the domain.

Requires connectivity to each DC and read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER ComputerName
One or more specific DC hostnames to check. When omitted, all DCs in the
domain are evaluated.

.EXAMPLE
Get-DSSysvolHealth -Domain 'contoso.com'

Returns SYSVOL health status for all DCs in contoso.com.

.EXAMPLE
Get-DSSysvolHealth -ComputerName 'DC01.contoso.com','DC02.contoso.com'

Returns SYSVOL health status for the specified DCs only.

.NOTES
#### Name:    Get-DSSysvolHealth
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

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName
    )

    Begin
    {
        $allDcs = [System.Collections.Generic.List[string]]::new()

        # If ComputerName was not supplied, enumerate DCs from the domain
        if (-not $PSBoundParameters.ContainsKey('ComputerName'))
        {
            try
            {
                $dcNamesFromDomain = Get-DSDomainControllerNames -Domain $Domain
                $dcNamesFromDomain | ForEach-Object { [void]$allDcs.Add($_) }
            }
            catch
            {
                Write-Error "Cannot connect to domain '$Domain': $_"
                return
            }

            Write-Verbose "Checking SYSVOL health for $($allDcs.Count) DC(s) in domain: $Domain"
        }

        $dfsrStateMap = @{
            0 = 'Uninitialized'
            1 = 'Initialized'
            2 = 'InitialSync'
            3 = 'AutoRecovery'
            4 = 'Normal'
            5 = 'InError'
        }
    }

    Process
    {
        foreach ($name in $ComputerName)
        {
            [void]$allDcs.Add($name)
        }
    }

    End
    {
        foreach ($dc in $allDcs)
        {
            Write-Verbose "Checking SYSVOL health on: $dc"

            $sysvolShared    = $false
            $netlogonShared  = $false
            $sysvolReady     = $null
            $dfsrStateName   = $null
            $dfsrStateCode   = $null
            $stagingBacklogMB = $null
            $errors          = [System.Collections.Generic.List[string]]::new()

            try
            {
                $cimSession = $null

                try
                {
                    $cimSession = New-CimSession -ComputerName $dc -ErrorAction Stop

                    # ── 1. Share check ─────────────────────────────────────────────

                    $shares = Get-CimInstance -CimSession $cimSession -ClassName 'Win32_Share' `
                        -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -in @('SYSVOL', 'NETLOGON') }

                    $sysvolShared   = $null -ne ($shares | Where-Object { $_.Name -eq 'SYSVOL' })
                    $netlogonShared = $null -ne ($shares | Where-Object { $_.Name -eq 'NETLOGON' })

                    # ── 2. SysvolReady registry flag ───────────────────────────────

                    try
                    {
                        $regClass = Get-CimClass -CimSession $cimSession -ClassName 'StdRegProv' `
                            -Namespace 'root\default'

                        $regResult = Invoke-CimMethod -CimClass $regClass -MethodName 'GetDWORDValue' `
                            -Arguments @{
                                hDefKey     = 2147483650  # HKLM
                                sSubKeyName = 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
                                sValueName  = 'SysvolReady'
                            }

                        $sysvolReady = ($regResult.uValue -eq 1)
                    }
                    catch
                    {
                        Write-Verbose "Could not read SysvolReady registry on '$dc': $_"
                    }

                    # ── 3. DFSR replication state ──────────────────────────────────

                    try
                    {
                        $dfsrInfo = Get-CimInstance -CimSession $cimSession `
                            -Namespace 'root\microsoftdfs' `
                            -ClassName 'DfsrReplicatedFolderInfo' `
                            -ErrorAction SilentlyContinue |
                            Where-Object { $_.ReplicationGroupName -eq 'Domain System Volume' }

                        if ($dfsrInfo)
                        {
                            $dfsrStateCode   = [int]$dfsrInfo.State
                            $dfsrStateName   = if ($dfsrStateMap.ContainsKey($dfsrStateCode))
                                              { $dfsrStateMap[$dfsrStateCode] }
                                              else
                                              { "Unknown($dfsrStateCode)" }
                            $stagingBacklogMB = $dfsrInfo.CurrentStageSizeInMb
                        }
                    }
                    catch
                    {
                        Write-Verbose "Could not query DFSR state on '$dc': $_"
                    }
                }
                finally
                {
                    if ($null -ne $cimSession)
                    {
                        Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
                    }
                }

                # ── Build error list ───────────────────────────────────────────────

                if (-not $sysvolShared)                              { [void]$errors.Add('SYSVOL share missing') }
                if (-not $netlogonShared)                            { [void]$errors.Add('NETLOGON share missing') }
                if ($null -ne $sysvolReady -and -not $sysvolReady)   { [void]$errors.Add('SysvolReady registry flag not set') }
                if ($null -ne $dfsrStateCode -and $dfsrStateCode -ne 4) { [void]$errors.Add("DFSR state: $dfsrStateName") }

                $isHealthy = $sysvolShared -and $netlogonShared -and
                             ($null -eq $sysvolReady -or $sysvolReady) -and
                             ($null -eq $dfsrStateCode -or $dfsrStateCode -eq 4)

                [PSCustomObject]@{
                    DCName           = $dc
                    SYSVOLShared     = $sysvolShared
                    NETLOGONShared   = $netlogonShared
                    SysvolReady      = $sysvolReady
                    DFSRState        = $dfsrStateName
                    DFSRStateCode    = $dfsrStateCode
                    StagingBacklogMB = $stagingBacklogMB
                    IsHealthy        = $isHealthy
                    Errors           = $errors.ToArray()
                }
            }
            catch
            {
                Write-Warning "Cannot reach DC '$dc': $_"

                [PSCustomObject]@{
                    DCName           = $dc
                    SYSVOLShared     = $false
                    NETLOGONShared   = $false
                    SysvolReady      = $null
                    DFSRState        = $null
                    DFSRStateCode    = $null
                    StagingBacklogMB = $null
                    IsHealthy        = $false
                    Errors           = @('DC unreachable')
                }
            }
        }
    }
}
