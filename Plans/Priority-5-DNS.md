# Implementation Plan — Priority 5: DNS Extensions

**Functions:** `Find-DSADIDNSRecord`, `Test-DSDNSSecurity`

---

## AD-Integrated DNS Background

AD-Integrated DNS stores zone data as `dnsNode` objects inside `dnsZone` containers.
Zones live in one of two application partitions:

| Partition | LDAP Path | Replication Scope |
|---|---|---|
| DomainDnsZones | `DC=DomainDnsZones,DC=<domain>,DC=<tld>` | All DCs in the domain |
| ForestDnsZones | `DC=ForestDnsZones,DC=<forest>,DC=<tld>` | All DCs in the forest |

Each zone is a container: `DC=<zoneName>,CN=MicrosoftDNS,DC=DomainDnsZones,...`

---

## Find-DSADIDNSRecord

### Attack Context

By default, `Authenticated Users` may have `Create Child` on zone containers,
allowing any domain user to add DNS records. Attackers add records for unresolved
names used by high-value services (WPAD, printer hostnames, etc.) to intercept
traffic or perform NTLM relay.

The wildcard `*` `dnsNode` record, if present, catches all unresolved queries in
the zone — a known attacker-planted indicator.

### Approach

Two passes:
1. **ACL pass** — check the zone container DACL for non-privileged write/create rights
2. **Wildcard record pass** — check for a `dnsNode` with `name = *`

### LDAP Query — Zone Containers

```
SearchRoot: DC=DomainDnsZones,<DomainDN>  (and DC=ForestDnsZones if -IncludeForestZones)
Filter: (objectClass=dnsZone)
Properties: name, distinguishedName, nTSecurityDescriptor
SecurityMasks: Dacl
```

### LDAP Query — Wildcard Node

For each zone:
```
SearchRoot: DC=<zoneName>,CN=MicrosoftDNS,DC=DomainDnsZones,...
Filter: (&(objectClass=dnsNode)(name=*))
Properties: distinguishedName, name, dnsRecord
```

> Note: The `*` wildcard must be escaped in the LDAP filter value.
> Use `\2a` for the wildcard character:
> `(&(objectClass=dnsNode)(name=\2a))`

### Rights to Flag on Zone Containers

Read `ObjectSecurity.Access` on each zone `DirectoryEntry` and flag ACEs with:
- `ActiveDirectoryRights.CreateChild` — can add new DNS records
- `ActiveDirectoryRights.WriteProperty` — can modify existing records
- `ActiveDirectoryRights.GenericWrite`
- `ActiveDirectoryRights.GenericAll`

### Principal Exclusions

Exclude these from "unexpected write access":
```
SYSTEM (S-1-5-18)
Domain Admins
Enterprise Admins
DnsAdmins (domain local group — look up by name)
Administrators
Domain Controllers
```

### Output Schema

```powershell
[PSCustomObject]@{
    ZoneName          = [string]
    DistinguishedName = [string]
    FindingType       = [string]   # 'UnexpectedWriteAccess' | 'WildcardRecord'
    Principal         = [string]   # SamAccountName/SID; $null for WildcardRecord findings
    Right             = [string]   # $null for WildcardRecord findings
    RecordName        = [string]   # '*' for wildcard; $null for ACL findings
    Partition         = [string]   # 'Domain' | 'Forest'
}
```

### Implementation Steps

1. `Begin {}` — build LDAP paths for domain partition; optionally add forest partition;
   resolve exclusion SIDs
2. `Process {}` — for each zone container:
   a. Read DACL via `SecurityMasks`; emit ACL findings
   b. Search for wildcard `dnsNode`; emit wildcard findings
3. If `-Zone` is specified, skip zones whose name does not match
4. `End {}` — dispose

### Notes

- `nTSecurityDescriptor` via searcher requires `SecurityMasks` set on the searcher:
  `$searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl`
- Accessing `DirectoryEntry.ObjectSecurity` on a zone object also works but requires
  an additional ADSI bind per object — use the SecurityMasks approach for efficiency

---

## Test-DSDNSSecurity

### Approach

Read DNS zone configuration attributes from each `dnsZone` object in the domain DNS
partition. Zone security settings are stored in the `dNSProperty` attribute as a
binary array of DNS_RPC_PROPERTY records — complex to parse directly.

**Preferred approach:** Use WMI class `MicrosoftDNS_Zone` in namespace
`root\MicrosoftDNS` against the PDC Emulator. This surfaces zone settings in a
structured, easily consumable form without binary parsing.

```powershell
$zones = Get-CimInstance -Namespace 'root\MicrosoftDNS' -ClassName 'MicrosoftDNS_Zone' -ComputerName $pdcEmulator
```

**Fallback approach** (if WMI unavailable): Parse `dNSProperty` binary attribute.

For the initial implementation, use WMI and note the dependency in `.DESCRIPTION`.

### Key WMI Properties

| Property | Description |
|---|---|
| `Name` | Zone DNS name |
| `ZoneType` | `0`=Cache, `1`=Primary, `2`=Secondary, `3`=Stub, `4`=Forwarder |
| `DynamicUpdate` | `0`=None, `1`=NonsecureAndSecure, `2`=Secure |
| `AllowedDCsForNsRecordsAutoCreation` | DCs allowed for NS auto-registration |
| `SecureSecondaries` | `0`=SendToAny, `1`=SendToNS, `2`=SendToList, `3`=NoTransfer |
| `SecondaryServers` | Array of allowed secondary server IPs |
| `Forwarders` | Conditional forwarder targets |
| `IsAutoCreated` | Internal zone |
| `IsReverseLookupZone` | Reverse lookup zone indicator |
| `IsPaused` | Zone paused |

### Security Evaluation Logic

```powershell
$unsecureDynamic  = $zone.DynamicUpdate -eq 1   # NonsecureAndSecure
$transfersEnabled = $zone.SecureSecondaries -ne 3 # 3 = NoTransfer

$riskFactors = @()
if ($unsecureDynamic)  { $riskFactors += 'UnsecuredDynamicUpdate' }
if ($transfersEnabled) { $riskFactors += 'ZoneTransferEnabled' }
if ($zone.SecureSecondaries -eq 0) { $riskFactors += 'ZoneTransferToAnyServer' }
```

### Output Schema

```powershell
[PSCustomObject]@{
    ZoneName                  = [string]
    ZoneType                  = [string]   # 'Primary' | 'Secondary' | 'Stub' etc.
    DynamicUpdate             = [string]   # 'None' | 'Secure' | 'NonsecureAndSecure'
    AllowsUnsecuredDynamic    = [bool]
    ZoneTransferEnabled       = [bool]
    ZoneTransferPolicy        = [string]   # 'NoTransfer' | 'ToNsServers' | 'ToList' | 'ToAny'
    ZoneTransferTargets       = [string[]] # IP list; $null if NoTransfer
    RiskFactors               = [string[]] # empty array if none
    IsReverseLookupZone       = [bool]
}
```

### Skip Criteria

Skip the following zone types (not relevant to security evaluation):
- `IsAutoCreated -eq $true`
- `IsReverseLookupZone -eq $true` (unless caller wants them)
- `ZoneType -eq 0` (cache zones)

### Implementation Steps

1. `Begin {}` — identify PDC Emulator via
   `[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx).PdcRoleOwner.Name`
2. Connect to WMI namespace `root\MicrosoftDNS` on PDC; query `MicrosoftDNS_Zone`
3. If `-Zone` specified, filter to matching zone name only
4. `Process {}` — for each zone, evaluate security settings; emit output object
5. `End {}` — close CIM session

### Tests

```
Tests/Unit/DNS/Test-DSDNSSecurity.Tests.ps1
```

Mock `Get-CimInstance` with a stub returning two zones:
1. Secure zone (DynamicUpdate=2, SecureSecondaries=3) — no risk factors
2. Insecure zone (DynamicUpdate=1, SecureSecondaries=0) — both risk factors flagged
