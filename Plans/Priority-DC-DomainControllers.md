# Implementation Plan — Domain Controllers

**Functions:** `Get-DSReplicationStatus`, `Get-DSSysvolHealth`

---

## Get-DSReplicationStatus

### Approach

Use the `[System.DirectoryServices.ActiveDirectory.DomainController]` class to access
replication metadata natively without RSAT. Each DC exposes replication neighbor data
via the `GetReplicationNeighbors()` method on a `DomainController` instance.

### Getting DomainController Objects

```powershell
$domainContext = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('Domain', $Domain)
$domain        = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
$domainControllers = $domain.DomainControllers  # collection of DomainController objects
$domain.Dispose()
```

### Reading Replication Data

For each DC:
```powershell
$dcContext = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new(
    'DirectoryServer', $dc.Name)
$dcObj     = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($dcContext)
$neighbors = $dcObj.GetReplicationNeighbors()  # returns ReplicationNeighborCollection
$dcObj.Dispose()
```

Each `ReplicationNeighbor` object exposes:

| Property | Type | Description |
|---|---|---|
| `SourceServer` | string | Replication partner DC name |
| `PartitionName` | string | Naming context (e.g. `DC=contoso,DC=com`) |
| `LastAttemptedSync` | DateTime | Last replication attempt |
| `LastSuccessfulSync` | DateTime | Last successful replication |
| `ConsecutiveFailureCount` | int | Consecutive failure count |
| `LastSyncResult` | int | Win32 error code (0 = success) |

### Output Schema

```powershell
[PSCustomObject]@{
    DCName                  = [string]
    Partner                 = [string]
    NamingContext           = [string]
    LastAttempted           = [DateTime]
    LastSuccessful          = [DateTime]
    ConsecutiveFailures     = [int]
    LastSyncResult          = [int]
    LastSyncResultMessage   = [string]   # Win32 error description, or 'Success'
    IsFailing               = [bool]    # ConsecutiveFailures -gt 0 or LastSyncResult -ne 0
}
```

### LastSyncResultMessage

Translate Win32 error codes to descriptions:
```powershell
$msg = if ($lastResult -eq 0) {
    'Success'
} else {
    ([System.ComponentModel.Win32Exception]$lastResult).Message
}
```

### ShowFailuresOnly Filter

When `-ShowFailuresOnly`:
```powershell
if ($ShowFailuresOnly -and -not $result.IsFailing) { continue }
```

### Error Handling

Wrap each DC's `GetDomainController()` call in `try/catch`:
- Unreachable DCs should emit `Write-Warning "Cannot connect to $($dc.Name): $_"` and continue
- Do not `throw` — partial results are more useful than no results

### Tests

```
Tests/Unit/DomainControllers/Get-DSReplicationStatus.Tests.ps1
```

---

## Get-DSSysvolHealth

### Approach

Check three distinct health indicators per DC:
1. **SYSVOL and NETLOGON shares** — via CIM/WMI `Win32_Share`
2. **SYSVOL ready flag** — via CIM registry read (`StdRegProv`)
3. **DFSR replication state** — via CIM `DfsrReplicatedFolderInfo`

Use CIM sessions for efficiency when checking multiple DCs.

### 1. Share Verification

```powershell
$shares = Get-CimInstance -ClassName Win32_Share -ComputerName $dc -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in @('SYSVOL', 'NETLOGON') }
$sysvolShared  = ($shares | Where-Object { $_.Name -eq 'SYSVOL'   }) -ne $null
$netlogonShared = ($shares | Where-Object { $_.Name -eq 'NETLOGON' }) -ne $null
```

### 2. SysvolReady Registry Flag

```powershell
$regClass  = Get-CimClass -ClassName StdRegProv -Namespace root\default -ComputerName $dc
$regResult = Invoke-CimMethod -CimClass $regClass -MethodName GetDWORDValue -Arguments @{
    hDefKey  = 2147483650  # HKLM
    sSubKeyName = 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    sValueName  = 'SysvolReady'
}
$sysvolReady = $regResult.uValue -eq 1
```

### 3. DFSR State

```powershell
$dfsrInfo = Get-CimInstance -Namespace 'root\microsoftdfs' `
    -ClassName 'DfsrReplicatedFolderInfo' `
    -ComputerName $dc `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.ReplicationGroupName -eq 'Domain System Volume' }
```

`DfsrReplicatedFolderInfo` key properties:

| Property | Description |
|---|---|
| `State` | `0`=Uninitialized, `1`=Initialized, `2`=InitialSync, `3`=AutoRecovery, `4`=Normal, `5`=InError |
| `ReplicationGroupName` | Should be `Domain System Volume` |
| `ReplicatedFolderName` | Should be `SYSVOL Share` |
| `CurrentStageSizeInMb` | Staging backlog in MB |
| `CurrentConflictSizeInMb` | Conflict backlog |

Map state integer to string:
```powershell
$stateNames = @{0='Uninitialized'; 1='Initialized'; 2='InitialSync'; 3='AutoRecovery'; 4='Normal'; 5='InError'}
$dfsrStateName = $stateNames[$dfsrState]
```

A `State` of `4` (Normal) is healthy; any other state warrants investigation.

### DC Enumeration

If `-ComputerName` is not provided, enumerate from domain:
```powershell
$domainContext = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('Domain', $Domain)
$domain        = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
$dcList        = $domain.DomainControllers | Select-Object -ExpandProperty Name
$domain.Dispose()
```

### Output Schema

```powershell
[PSCustomObject]@{
    DCName              = [string]
    SYSVOLShared        = [bool]
    NETLOGONShared      = [bool]
    SysvolReady         = [bool]     # Registry flag; $null if unreadable
    DFSRState           = [string]   # 'Normal' | 'InitialSync' | 'InError' | etc.; $null if unavailable
    DFSRStateCode       = [int]      # Raw integer; $null if unavailable
    StagingBacklogMB    = [float]    # $null if unavailable
    IsHealthy           = [bool]     # SYSVOLShared -and NETLOGONShared -and SysvolReady -and DFSRState eq 'Normal'
    Errors              = [string[]] # List of detected problems; empty if IsHealthy
}
```

### Error Collection Logic

```powershell
$errors = @()
if (-not $sysvolShared)    { $errors += 'SYSVOL share missing' }
if (-not $netlogonShared)  { $errors += 'NETLOGON share missing' }
if (-not $sysvolReady)     { $errors += 'SysvolReady registry flag not set' }
if ($dfsrState -ne 4)      { $errors += "DFSR state: $dfsrStateName" }
```

### Error Handling

Wrap each DC check in `try/catch`. Unreachable DCs should emit a result with
`IsHealthy = $false` and `Errors = @('DC unreachable')` rather than throwing.

### Tests

```
Tests/Unit/DomainControllers/Get-DSSysvolHealth.Tests.ps1
```

Mock `Get-CimInstance` for `Win32_Share` and `DfsrReplicatedFolderInfo`.
Test cases:
1. Healthy DC — all checks pass, `IsHealthy = $true`, `Errors` is empty
2. Missing SYSVOL share — `SYSVOLShared = $false`, `IsHealthy = $false`
3. DFSR in InError state — `IsHealthy = $false`, `Errors` contains DFSR message
