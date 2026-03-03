# Implementation Plan — Priority 4: Trust & Forest Relationships

**Functions:** `Get-DSTrustRelationship`, `Test-DSTrustSIDFiltering`

---

## Shared Context

Trust objects are stored as `trustedDomain` class objects under
`CN=System,<DomainDN>`. They can be read via a standard LDAP search with
`objectClass=trustedDomain`.

The existing `ConvertFrom-TrustAttributeValue` function handles decoding the
`trustAttributes` integer — use it here.

**Trust direction constants:**
| Value | Meaning |
|---|---|
| `1` | Inbound (the domain trusts us) |
| `2` | Outbound (we trust the domain) |
| `3` | Bidirectional |

**Trust type constants:**
| Value | Meaning |
|---|---|
| `1` | Windows NT (downlevel) |
| `2` | Active Directory (Kerberos) |
| `3` | MIT Kerberos realm |
| `4` | DCE |

**Trust attribute flags (key ones):**
| Bit | Hex | Name |
|---|---|---|
| `1` | `0x01` | `TRUST_ATTRIBUTE_NON_TRANSITIVE` |
| `2` | `0x02` | `TRUST_ATTRIBUTE_UPLEVEL_ONLY` |
| `4` | `0x04` | `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN` (SID filtering) |
| `8` | `0x08` | `TRUST_ATTRIBUTE_FOREST_TRANSITIVE` |
| `16` | `0x10` | `TRUST_ATTRIBUTE_CROSS_ORGANIZATION` |
| `32` | `0x20` | `TRUST_ATTRIBUTE_WITHIN_FOREST` |
| `64` | `0x40` | `TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL` |
| `512` | `0x200` | `TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION` |

---

## Get-DSTrustRelationship

### LDAP Query

```
SearchRoot: LDAP://CN=System,<DomainDN>
Filter: (objectClass=trustedDomain)
SearchScope: OneLevel   # trusts are direct children of CN=System
```

### Properties to Load

```
name, trustDirection, trustType, trustAttributes,
securityIdentifier, flatName, whenCreated, whenChanged,
trustAuthOutgoing, trustAuthIncoming
```

`securityIdentifier` — raw bytes of the trusted domain's SID; convert with:
```powershell
$sidBytes = $result.Properties['securityidentifier'][0]
$sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
```

### TrustType — Human-Readable Name

Derive `TrustTypeName` from `trustType` int + key `trustAttributes` flags:

```powershell
$typeName = switch ($trustType)
{
    1 { 'DownlevelNT' }
    2 {
        if ($trustAttributes -band 8)  { 'Forest' }
        elseif ($trustAttributes -band 32) { 'ParentChild' }
        elseif ($trustAttributes -band 64) { 'External' }
        else { 'External' }
    }
    3 { 'MITKerberos' }
    4 { 'DCE' }
    default { "Unknown($trustType)" }
}
```

### Transitivity

`IsTransitive = -not ($trustAttributes -band 1)`
(The `NON_TRANSITIVE` flag being absent means the trust is transitive.)

Forest trusts (`TRUST_ATTRIBUTE_FOREST_TRANSITIVE`) are always transitive.

### Forest-Wide Enumeration (`-IncludeForest`)

When `-IncludeForest` is set:
1. Enumerate all domains in the forest via
   `[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains`
2. For each domain, repeat the LDAP query using that domain's DN as SearchRoot
3. Tag each result with `SourceDomain` to indicate which domain the trust was read from
4. Deduplicate symmetric bidirectional trusts (same pair seen from both sides) — keep both entries
   but mark `SourceDomain` appropriately

### Output Schema

```powershell
[PSCustomObject]@{
    Name              = [string]    # DNS name of the trusted domain
    FlatName          = [string]    # NetBIOS name
    TrustedDomainSID  = [string]    # SID of trusted domain
    Direction         = [string]    # 'Inbound' | 'Outbound' | 'Bidirectional'
    TrustType         = [string]    # 'Forest' | 'External' | 'ParentChild' | etc.
    IsTransitive      = [bool]
    ForestTransitive  = [bool]      # TRUST_ATTRIBUTE_FOREST_TRANSITIVE
    SIDFilteringEnabled = [bool]    # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
    TGTDelegationBlocked = [bool]   # TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION
    WithinForest      = [bool]      # TRUST_ATTRIBUTE_WITHIN_FOREST
    TreatAsExternal   = [bool]      # TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL
    TrustAttributes   = [int]       # raw integer for full decode via ConvertFrom-TrustAttributeValue
    WhenCreated       = [DateTime]
    WhenModified      = [DateTime]
    SourceDomain      = [string]    # populated only with -IncludeForest
}
```

### Implementation Steps

1. `Begin {}` — build `SearchRoot` for `CN=System,<DomainDN>`; resolve domain DN from domain name
2. `Process {}` — run OneLevel search; foreach result, decode direction/type/attributes; emit object
3. If `-IncludeForest` — iterate forest domains; for each, create a new searcher pointed at that
   domain's System container; collect and tag results
4. `End {}` — dispose

---

## Test-DSTrustSIDFiltering

### Approach

This function is a focused wrapper over `Get-DSTrustRelationship`. It calls
`Get-DSTrustRelationship` internally (or duplicates the query — the latter
avoids a public dependency between functions in the same module) and evaluates
the SID filtering status for each trust.

**Recommendation:** Duplicate the query rather than calling `Get-DSTrustRelationship`
to keep functions independently testable and avoid tight coupling. The query is
small (trust objects are few).

### SID Filtering Logic

SID filtering status is derived from multiple attributes:

```powershell
$sidFilteringEnabled = $trustAttributes -band 4   # QUARANTINED_DOMAIN

# For forest trusts: SID filtering is on by default unless explicitly disabled.
# The absence of QUARANTINED_DOMAIN on a forest trust is still SID-filtered
# via forest claims. Only cross-forest + non-quarantined is truly concerning.
$isForestTrust   = $trustAttributes -band 8
$isExternal      = -not $isForestTrust -and -not ($trustAttributes -band 32)

$filteringStatus = if ($sidFilteringEnabled) {
    'Enabled'
} elseif ($isForestTrust) {
    'ForestDefault'   # forest trust, no explicit quarantine but filter applies at forest boundary
} elseif ($isExternal) {
    'Disabled'        # external trust without quarantine — HIGH RISK
} else {
    'WithinForest'    # parent-child or shortcut within forest; SID filtering always on
}
```

### Risk Rating

| FilteringStatus | Risk |
|---|---|
| `Enabled` | Low — SID filtering explicitly enforced |
| `ForestDefault` | Medium — forest boundary provides some isolation |
| `WithinForest` | Low — intra-forest, SID filtering always on |
| `Disabled` | **High** — SID history attacks possible |

### Output Schema

```powershell
[PSCustomObject]@{
    TrustName         = [string]
    Direction         = [string]
    TrustType         = [string]
    SIDFilteringEnabled = [bool]
    FilteringStatus   = [string]   # 'Enabled' | 'ForestDefault' | 'Disabled' | 'WithinForest'
    RiskLevel         = [string]   # 'High' | 'Medium' | 'Low'
    TrustAttributes   = [int]
}
```

### Tests

```
Tests/Unit/Trusts/Test-DSTrustSIDFiltering.Tests.ps1
```

Mock three trust objects:
1. External trust with `QUARANTINED_DOMAIN` set → `Enabled` / `Low`
2. External trust without quarantine → `Disabled` / `High`
3. Forest trust without quarantine → `ForestDefault` / `Medium`
