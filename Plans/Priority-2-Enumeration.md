# Implementation Plan — Priority 2: High Value Enumeration

**Functions:** `Get-DSAdminAccounts`, `Get-DSServiceAccounts`, `Get-DSAdminSDHolder`,
`Get-DSComputerByProperty`, `Get-DSGPO`

---

## Get-DSAdminAccounts

### Approach

For each protected group, use the LDAP transitive membership matching rule
(`1.2.840.113556.1.4.1941` — `LDAP_MATCHING_RULE_IN_CHAIN`) to enumerate all
direct and nested members in a single query. This avoids manual recursion and
handles arbitrarily deep nesting.

### Protected Groups to Query (defaults)

Resolve each group's DN at runtime by searching for `(sAMAccountName=<name>)` under
the domain root. Use resolved DNs for the transitive membership filter.

```
Domain Admins, Enterprise Admins, Schema Admins,
Administrators, Protected Users
```

### LDAP Filter (per group)

```
(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=<GroupDN>))
```

Run once per group in `$Groups`. Deduplicate results by `distinguishedName` across
groups (an account may appear in multiple groups).

### Properties to Load

```
distinguishedName, sAMAccountName, userAccountControl,
pwdLastSet, lastLogonTimestamp, memberOf
```

### Output Schema

```powershell
[PSCustomObject]@{
    SamAccountName    = [string]
    DistinguishedName = [string]
    Enabled           = [bool]
    PasswordLastSet   = [DateTime]
    LastLogon         = [DateTime]  # from lastLogonTimestamp (FILETIME), ~14-day accuracy
    Groups            = [string[]]  # which protected group(s) this account satisfies
}
```

### Implementation Steps

1. `Begin {}` — connect to domain; resolve each group name in `$Groups` to a DN via searcher
2. `Process {}` — foreach group DN, run transitive membership query; track seen DNs with a
   `[System.Collections.Generic.HashSet[string]]` to deduplicate
3. Emit one object per unique account, with `Groups` array listing all matched groups
4. `End {}` — dispose

### Notes

- Enterprise Admins and Schema Admins live in the root domain of the forest, not necessarily
  the queried domain. Detect via `$DomainEntry.Forest.RootDomain.Name` and adjust `SearchRoot` accordingly.
- `lastLogonTimestamp` is FILETIME; convert with `[DateTime]::FromFileTime()`. Value `0` means
  never logged on — handle as `$null`.

### Tests

```
Tests/Unit/Enumeration/Get-DSAdminAccounts.Tests.ps1
```

---

## Get-DSServiceAccounts

### Approach

Two LDAP queries combined: (1) accounts with SPNs, (2) accounts matching
description keywords. Merge and deduplicate. OU-pattern matching is done
post-query on the `distinguishedName` string.

### LDAP Filters

**SPN-based:**
```
(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt)))
```

**Description-based:**
```
(&(objectClass=user)(|(description=*svc*)(description=*service*)(description=*scheduled*)(description=*task*)(description=*app*)))
```

> Note: LDAP does not support regex; substring match `*keyword*` is the available operator.

### OU Pattern Detection (post-query)

After collecting results, flag entries whose `distinguishedName` contains any of:
```
ServiceAccount, SvcAcct, Service, SA_, _svc
```
(case-insensitive string match on the OU portion of the DN)

### Properties to Load

```
distinguishedName, sAMAccountName, servicePrincipalName, description,
userAccountControl, pwdLastSet, memberOf
```

### Output Schema

```powershell
[PSCustomObject]@{
    SamAccountName      = [string]
    DistinguishedName   = [string]
    SPNs                = [string[]]
    Description         = [string]
    Enabled             = [bool]
    PasswordNeverExpires = [bool]   # UAC bit 65536
    PasswordLastSet     = [DateTime]
    DetectedBy          = [string[]] # e.g. @('SPN', 'Description', 'OU')
}
```

### Implementation Steps

1. Run both queries, collect results into a single `[System.Collections.Generic.Dictionary[string, object]]`
   keyed by `distinguishedName` to deduplicate
2. For each unique entry, post-process the `DetectedBy` array
3. Emit output objects

---

## Get-DSAdminSDHolder

### Approach

1. Query all objects with `adminCount=1`
2. Independently build the set of current protected group members using the same
   transitive membership pattern as `Get-DSAdminAccounts`
3. Cross-reference: any `adminCount=1` object **not** in the current protected member
   set is flagged as an unexpected residual

### LDAP Filter (adminCount)

```
(&(objectCategory=person)(adminCount=1))
```

Also run for computer objects (rare but possible):
```
(&(objectCategory=computer)(adminCount=1))
```

### Protected Groups (for cross-reference)

Same list as `Get-DSAdminAccounts` plus:
```
Backup Operators, Account Operators, Server Operators,
Print Operators, Group Policy Creator Owners, Replicator, krbtgt
```

### Output Schema

```powershell
[PSCustomObject]@{
    SamAccountName         = [string]
    DistinguishedName      = [string]
    ObjectClass            = [string]
    Enabled                = [bool]
    AdminCount             = [int]       # will always be 1
    IsCurrentProtectedMember = [bool]   # $false = residual/unexpected
}
```

### Implementation Steps

1. `Begin {}` — query all `adminCount=1` objects; build `$adminCountSet` (HashSet by DN)
2. Build `$currentProtectedMembers` HashSet by querying each protected group transitively
3. `Process {}` — emit each `adminCount=1` object with `IsCurrentProtectedMember` flag
4. When `-IncludeExpected` is **not** set, filter to only `IsCurrentProtectedMember -eq $false`

---

## Get-DSComputerByProperty

### Approach

Single configurable LDAP query. Build the filter dynamically from parameters provided.
Follow the same pattern as `Get-DSUserByProperty` but for computer objects.

### LDAP Filter Construction

Base filter: `(objectCategory=computer)`

Append conditions based on parameters:

| Parameter | Additional Clause |
|---|---|
| `-OperatingSystem 'Windows Server 2019*'` | `(operatingSystem=Windows Server 2019*)` |
| `-Enabled $true` | `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` |
| `-Enabled $false` | `(userAccountControl:1.2.840.113556.1.4.803:=2)` |
| `-InactiveDays 90` | `(lastLogonTimestamp<=$fileTimeThreshold)` |

Combine with `(&...all clauses...)`.

`$fileTimeThreshold = (Get-Date).AddDays(-$InactiveDays).ToFileTime()`

### SearchRoot

If `-SearchBase` is provided:
```powershell
$searcher.SearchRoot = [adsi]"LDAP://$SearchBase"
```
Otherwise use domain root.

### Properties to Load

```
name, sAMAccountName, distinguishedName, operatingSystem, operatingSystemVersion,
userAccountControl, lastLogonTimestamp, pwdLastSet, dNSHostName
```

### Output Schema

```powershell
[PSCustomObject]@{
    Name                    = [string]
    SamAccountName          = [string]
    DistinguishedName       = [string]
    DNSHostName             = [string]
    OperatingSystem         = [string]
    OperatingSystemVersion  = [string]
    Enabled                 = [bool]
    PasswordLastSet         = [DateTime]
    LastLogonTimestamp      = [DateTime]  # $null if never
    DaysSinceLastLogon      = [int]       # $null if never
}
```

---

## Get-DSGPO

### Approach

GPO objects live under `CN=Policies,CN=System,DC=...` with `objectClass=groupPolicyContainer`.
GPO links are stored in the `gpLink` attribute on domain, OU, and site objects — a
multi-value string in the format:
```
[LDAP://cn={GUID},cn=policies,cn=system,DC=...;X][LDAP://...;Y]
```
where `X` is the link options bitmask:
- `0` = Link enabled, not enforced
- `1` = Link disabled
- `2` = Link enforced (non-editable by child)
- `3` = Disabled and enforced

### Two-Pass Approach

**Pass 1 — Enumerate GPOs:**

```
LDAP filter: (objectClass=groupPolicyContainer)
SearchRoot: CN=Policies,CN=System,<DomainDN>
Properties: displayName, cn, gPCFileSysPath, gPCFunctionalityVersion, versionNumber,
            whenCreated, whenChanged, flags, gPCWQLFilter
```

`flags` attribute on groupPolicyContainer:
- `0` = All settings enabled
- `1` = User configuration disabled
- `2` = Computer configuration disabled
- `3` = All settings disabled

**Pass 2 — Enumerate Links:**

Search domain, all OUs, and all sites for objects with `gpLink=*`:
```
LDAP filter: (gpLink=*)
Properties: distinguishedName, gpLink, gpOptions
```

`gpOptions` on an OU: `1` = inheritance blocked; `0` = inheritance not blocked.

Parse each `gpLink` value with a regex to extract GPO GUIDs and link option flags.
Build a lookup table `[GUID → @( {LinkedTo, Enabled, Enforced} )]`.

### Output Schema

```powershell
[PSCustomObject]@{
    DisplayName       = [string]
    GPOId             = [string]       # the CN GUID value, e.g. {A1B2C3...}
    WhenCreated       = [DateTime]
    WhenModified      = [DateTime]
    UserSettingsEnabled   = [bool]
    ComputerSettingsEnabled = [bool]
    WMIFilter         = [string]       # $null if no WMI filter
    Links             = [PSCustomObject[]]  # see below
    IsLinked          = [bool]         # $Links.Count -gt 0
}

# Each Links entry:
[PSCustomObject]@{
    LinkedTo        = [string]  # DN of the OU/domain/site
    LinkEnabled     = [bool]
    LinkEnforced    = [bool]
    InheritanceBlocked = [bool] # gpOptions on the container
}
```

### Implementation Steps

1. `Begin {}` — build domain context; query all GPOs into a `[hashtable]` keyed by GPO CN (GUID)
2. Query all `gpLink=*` objects; parse links; populate `Links` property on matching GPOs
3. `Process {}` — emit GPO objects; apply `-LinkedOnly` or `-HighValueOUsOnly` filters
4. High-value OU detection: check if `LinkedTo` DN contains `Domain Controllers` or matches
   common admin workstation OU names

### Notes

- Site links live in `CN=Sites,CN=Configuration,<ForestDN>` — out of scope for initial implementation;
  add a `-IncludeSiteLinks` switch in a future version
- WMI filter: `gPCWQLFilter` contains the DN of the WMI filter object if set

### Tests

```
Tests/Unit/Enumeration/Get-DSGPO.Tests.ps1
```

Mock: two GPO objects, one linked (to Domain Controllers OU), one unlinked.
Test: `-LinkedOnly` returns only the linked GPO; output schema has all properties.
