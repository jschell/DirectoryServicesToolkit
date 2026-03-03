# Implementation Plan — Priority 1: Critical Attack Surface

**Functions:** `Find-DSDelegation`, `Find-DSKerberoastable`, `Find-DSASREPRoastable`, `Find-DSInterestingACE`

**Rationale:** These four functions cover the most common modern AD attack entry points.
All require only read access to the domain partition. Implement in the order listed —
each builds familiarity with the pattern needed for the next.

---

## Shared Implementation Notes

All four functions follow the paged-searcher pattern from `Get-DSKeyCredLink`:

```powershell
$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
$DomainEntry   = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
$DomainName    = $DomainEntry.Name
$DomainEntry.Dispose()
$ldapPath = "LDAP://$DomainName"
$searcher = [adsisearcher][adsi]$ldapPath
$searcher.PageSize  = 1000
$searcher.SizeLimit = 0
```

Use `[System.Collections.ArrayList]` for result accumulation. Dispose searcher in `End {}`.

LDAP bitwise OID for UAC checks: `1.2.840.113556.1.4.803`
LDAP transitive membership OID: `1.2.840.113556.1.4.1941`

---

## Find-DSDelegation

### Approach

Three separate LDAP queries, combined into a single result stream.

### LDAP Filters

| Type | Filter |
|---|---|
| Unconstrained (users) | `(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=524288))` |
| Unconstrained (computers) | `(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))` |
| Constrained | `(&(objectClass=user)(msDS-AllowedToDelegateTo=*))` |
| RBCD | `(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))` |

UAC bits:
- `524288` (0x80000) — `TRUSTED_FOR_DELEGATION` (unconstrained)
- `16777216` (0x1000000) — `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` (protocol transition; check alongside constrained)
- `2` (0x2) — `ACCOUNTDISABLE`

To exclude computer accounts when `-ExcludeComputerAccounts` is set, skip the two computer queries
and add `(!(objectCategory=computer))` to constrained filter.

### Properties to Load

```
distinguishedName, sAMAccountName, userAccountControl,
msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfOtherIdentity, servicePrincipalName
```

### Output Schema

```powershell
[PSCustomObject]@{
    SamAccountName    = [string]
    DistinguishedName = [string]
    DelegationType    = [string]   # 'Unconstrained' | 'Constrained' | 'RBCD'
    ProtocolTransition = [bool]    # $true if UAC has TRUSTED_TO_AUTH bit set
    DelegationTarget  = [string[]] # msDS-AllowedToDelegateTo values, or $null for Unconstrained/RBCD
    RBCDTarget        = [string]   # raw binary of msDS-AllowedToActOnBehalfOfOtherIdentity, or $null
    Enabled           = [bool]     # !($uac -band 2)
    ObjectType        = [string]   # 'User' | 'Computer'
}
```

### Implementation Steps

1. `Begin {}` — build LDAP path, set up domain context
2. `Process {}` — run each query block conditionally based on `$DelegationType` parameter:
   - `'All'` or `'Unconstrained'` → run unconstrained user + computer queries
   - `'All'` or `'Constrained'` → run constrained query
   - `'All'` or `'RBCD'` → run RBCD query
3. Per result, emit one `[PSCustomObject]` with the schema above
4. `End {}` — dispose searcher(s)

### Edge Cases

- An account can have both constrained AND protocol transition set; `ProtocolTransition` flag handles this
- RBCD: `msDS-AllowedToActOnBehalfOfOtherIdentity` is a binary security descriptor — return raw bytes or a parsed
  string of allowed principals (use `[System.Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0)`)
- Exclude `krbtgt` from results (filter `(!(cn=krbtgt))`)

### Tests

```
Tests/Unit/Security/Find-DSDelegation.Tests.ps1
```

Mock `[adsisearcher]` via a helper stub that returns pre-built result objects for each delegation type.
Test that:
- `-DelegationType Unconstrained` returns only unconstrained entries
- `-ExcludeComputerAccounts` removes entries where `ObjectType -eq 'Computer'`
- Output objects have all required properties populated

---

## Find-DSKerberoastable

### Approach

Single LDAP query with optional disabled-account filter.

### LDAP Filters

Base (enabled accounts only):
```
(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

With `-IncludeDisabled` — remove the UAC disabled condition:
```
(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt)))
```

With `-ExcludeManagedAccounts` — append:
```
(!(objectClass=msDS-GroupManagedServiceAccount))(!(objectClass=msDS-ManagedServiceAccount))
```

### Properties to Load

```
distinguishedName, sAMAccountName, servicePrincipalName,
userAccountControl, pwdLastSet, memberOf
```

### Output Schema

```powershell
[PSCustomObject]@{
    SamAccountName    = [string]
    DistinguishedName = [string]
    SPNs              = [string[]]  # all values of servicePrincipalName
    PasswordLastSet   = [DateTime]
    PasswordAgeDays   = [int]       # (Get-Date) - PasswordLastSet, in days
    Enabled           = [bool]
    IsManagedAccount  = [bool]      # objectClass contains msDS-*ServiceAccount
}
```

### Implementation Steps

1. `Begin {}` — compute LDAP filter string based on switch parameters
2. `Process {}` — run single paged query, emit one object per result
3. `End {}` — dispose searcher

### Notes

- `pwdLastSet` stored as FILETIME (Int64); convert with `[DateTime]::FromFileTime($val)`
- `servicePrincipalName` is multi-valued; retrieve as `$result.Properties['serviceprincipalname']` — returns a collection
- Sort output by `PasswordAgeDays` descending (oldest password first = highest priority)

### Tests

```
Tests/Unit/Security/Find-DSKerberoastable.Tests.ps1
```

Test: disabled accounts excluded by default; included with `-IncludeDisabled`; krbtgt never appears;
managed accounts excluded with `-ExcludeManagedAccounts`.

---

## Find-DSASREPRoastable

### Approach

Single LDAP query. Simplest of the four Priority 1 functions.

### LDAP Filter

```
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

UAC bit `4194304` (0x400000) = `DONT_REQUIRE_PREAUTH`

With `-IncludeDisabled` — remove the disabled exclusion clause.

### Properties to Load

```
distinguishedName, sAMAccountName, userAccountControl, memberOf, pwdLastSet
```

### Output Schema

```powershell
[PSCustomObject]@{
    SamAccountName    = [string]
    DistinguishedName = [string]
    Enabled           = [bool]
    PasswordLastSet   = [DateTime]
    MemberOf          = [string[]]  # direct group memberships
}
```

### Tests

```
Tests/Unit/Security/Find-DSASREPRoastable.Tests.ps1
```

---

## Find-DSInterestingACE

### Approach

Enumerate AD objects via DirectorySearcher; for each result read the DACL via
`[System.DirectoryServices.DirectoryEntry].ObjectSecurity.Access`. This is more
expensive than attribute queries — `-SearchBase` scoping is strongly recommended
for large domains.

### Rights to Flag

| Right | ActiveDirectoryRights value |
|---|---|
| GenericAll | `0x10000000` / `268435456` |
| GenericWrite | `0x40000000` / `1073741824` |
| WriteDACL | `0x00040000` / `262144` |
| WriteOwner | `0x00080000` / `524288` |
| AllExtendedRights | Use `AccessControlType -eq 'Allow'` + `ObjectType -eq Guid.Empty` with right `ExtendedRight` |
| ForceChangePassword | Extended right GUID: `00299570-246d-11d0-a768-00aa006e0529` |
| Self (SPN write) | Extended right GUID: `f3a64788-5306-11d1-a9c5-0000f80367c1` |
| Self (msDS-KeyCredentialLink) | Property set or attribute GUID |

### Well-Known Admin SIDs to Exclude (when `-ExcludeAdmins`)

Resolve these at runtime against the target domain rather than hard-coding:
```
Domain Admins, Enterprise Admins, SYSTEM (S-1-5-18),
Administrators (S-1-5-32-544), Domain Controllers
```

Resolve via SID lookup: `New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')`
and match against `$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])`.

### LDAP Filter (objects to enumerate)

```
(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit))
```

Restrict to `$SearchBase` if provided; otherwise search from domain root.

### Properties to Load

```
distinguishedName, sAMAccountName, objectClass, nTSecurityDescriptor
```

**Note:** To read `nTSecurityDescriptor`, the searcher must have `SecurityMasks` set:

```powershell
$searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
```

### Output Schema

```powershell
[PSCustomObject]@{
    TargetObject      = [string]   # DistinguishedName of object with the ACE
    TargetObjectClass = [string]
    Principal         = [string]   # SamAccountName or SID of the ACE identity
    Right             = [string]   # Human-readable right name
    AccessType        = [string]   # 'Allow' | 'Deny'
    IsInherited       = [bool]
}
```

### Implementation Steps

1. `Begin {}` — build domain context; resolve admin SIDs to exclude; compile list of flagged right values
2. `Process {}` — paged search; for each result, instantiate `[System.DirectoryServices.DirectoryEntry]`
   with the result DN; read `$entry.ObjectSecurity.Access`; iterate ACEs; filter by rights; emit result objects
3. `End {}` — dispose

### Performance Notes

- Large domains: default `SizeLimit = 1000`; document this limitation
- Each object requires an additional ADSI bind to read its security descriptor — avoid in very large scopes
- `-SearchBase` targeting a sensitive OU (e.g. `OU=Users`, `OU=ServiceAccounts`) is the typical usage

### Tests

```
Tests/Unit/Security/Find-DSInterestingACE.Tests.ps1
```

Mock `DirectoryEntry.ObjectSecurity.Access` via a stub class or Pester mock.
Test: GenericAll ACE is flagged; inherited ACEs excluded by default; `-IncludeInherited` includes them.
