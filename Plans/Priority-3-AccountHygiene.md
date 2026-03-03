# Implementation Plan — Priority 3: Password & Account Hygiene

**Functions:** `Get-DSPasswordPolicy`, `Find-DSPasswordNotRequired`,
`Find-DSPasswordNeverExpires`, `Find-DSStaleAccounts`

---

## Get-DSPasswordPolicy

### Approach

Two separate reads:

1. **Default Domain Policy** — read from the domain root object (`DC=domain,DC=com`)
   using `[System.DirectoryServices.DirectoryEntry]`.
2. **Fine-Grained Password Policies (PSOs)** — LDAP search under
   `CN=Password Settings Container,CN=System,<DomainDN>`.

### Default Domain Policy Attributes

Read directly from the domain root `DirectoryEntry`:

| Attribute | Description | Conversion |
|---|---|---|
| `maxPwdAge` | Maximum password age | Negative FILETIME interval → `[TimeSpan]::FromTicks(-$val)` |
| `minPwdAge` | Minimum password age | Same negative interval conversion |
| `minPwdLength` | Minimum length | Direct int |
| `pwdHistoryLength` | History count | Direct int |
| `pwdProperties` | Complexity bitmask | Bit `1` = complexity required |
| `lockoutThreshold` | Lockout attempts | Direct int |
| `lockoutDuration` | Lockout duration | Negative interval conversion |
| `lockoutObservationWindow` | Reset counter window | Negative interval conversion |

```powershell
$domainEntry = [adsi]"LDAP://$DomainName"
$maxPwdAge   = $domainEntry.Properties['maxPwdAge'][0]
# Convert: [TimeSpan]::FromTicks( [Math]::Abs($maxPwdAge) )
```

### PSO LDAP Filter

```
(objectClass=msDS-PasswordSettings)
```

SearchRoot: `LDAP://CN=Password Settings Container,CN=System,<DomainDN>`

### PSO Attributes to Load

```
name, msDS-PasswordSettingsPrecedence, msDS-MaximumPasswordAge,
msDS-MinimumPasswordAge, msDS-MinimumPasswordLength,
msDS-PasswordHistoryLength, msDS-LockoutThreshold,
msDS-LockoutDuration, msDS-LockoutObservationWindow,
msDS-PasswordComplexityEnabled, msDS-PasswordReversibleEncryptionEnabled,
msDS-PSOAppliesTo
```

All interval attributes (`msDS-MaximumPasswordAge`, etc.) use the same negative FILETIME
interval conversion as the default policy.

`msDS-PSOAppliesTo` is multi-valued; contains DNs of users or groups the PSO applies to.

### Output Schema

Default domain policy:
```powershell
[PSCustomObject]@{
    PolicyType            = 'Default'
    Name                  = 'Default Domain Policy'
    MinPasswordLength     = [int]
    PasswordHistoryCount  = [int]
    MaxPasswordAge        = [TimeSpan]
    MinPasswordAge        = [TimeSpan]
    LockoutThreshold      = [int]
    LockoutDuration       = [TimeSpan]
    LockoutObservationWindow = [TimeSpan]
    ComplexityEnabled     = [bool]
    ReversibleEncryption  = [bool]
    Precedence            = $null
    AppliesTo             = $null
}
```

PSO (same schema, plus):
```powershell
    PolicyType  = 'FineGrained'
    Precedence  = [int]
    AppliesTo   = [string[]]  # DNs of target users/groups
```

### Implementation Steps

1. `Begin {}` — build domain root path; read default policy attributes
2. Emit default policy object immediately
3. If `$IncludeFineGrained` — search PSO container; emit one object per PSO
4. `End {}` — dispose

---

## Find-DSPasswordNotRequired

### LDAP Filter

Enabled accounts only (default):
```
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

With `-IncludeDisabled` — remove the disabled exclusion:
```
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))
```

UAC bit `32` (0x20) = `PASSWD_NOTREQD`

### Properties to Load

```
distinguishedName, sAMAccountName, userAccountControl, pwdLastSet, memberOf
```

### Output Schema

```powershell
[PSCustomObject]@{
    SamAccountName    = [string]
    DistinguishedName = [string]
    Enabled           = [bool]
    PasswordLastSet   = [DateTime]   # $null if pwdLastSet is 0
    PasswordNeverSet  = [bool]       # $true if pwdLastSet eq 0
}
```

### Notes

- `pwdLastSet = 0` means the password has never been set, which is the blank-password
  risk scenario. Surface this explicitly via `PasswordNeverSet`.
- Emit `Write-Warning` if result count exceeds 10 — large counts indicate a bulk provisioning
  hygiene problem worth calling attention to.

---

## Find-DSPasswordNeverExpires

### LDAP Filter

Enabled accounts only (default):
```
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

UAC bit `65536` (0x10000) = `DONT_EXPIRE_PASSWORD`

With `-IncludeDisabled` — remove the disabled exclusion.

### Properties to Load

```
distinguishedName, sAMAccountName, userAccountControl,
pwdLastSet, servicePrincipalName
```

### Output Schema

```powershell
[PSCustomObject]@{
    SamAccountName    = [string]
    DistinguishedName = [string]
    Enabled           = [bool]
    PasswordLastSet   = [DateTime]
    PasswordAgeDays   = [int]        # days since PasswordLastSet; $null if never set
    HasSPN            = [bool]       # cross-reference with Kerberoast candidates
    SPNs              = [string[]]   # $null if HasSPN is $false
}
```

### Notes

- `HasSPN` makes it trivial for a consumer to pipe results and filter to
  `Where-Object HasSPN` to get the highest-risk Kerberoastable overlap.
- Sort output by `PasswordAgeDays` descending.

---

## Find-DSStaleAccounts

### Approach

Two LDAP queries (users and computers), controlled by `-ObjectType`. Uses
`lastLogonTimestamp` (replicated, ~14-day accuracy) rather than `lastlogon`
(non-replicated per DC).

### Threshold Calculation

```powershell
$thresholdDate     = (Get-Date).AddDays(-$ThresholdDays)
$thresholdFileTime = $thresholdDate.ToFileTime()
```

### LDAP Filters

**Users:**
```
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$thresholdFileTime))
```

UAC bit `512` (0x200) = `NORMAL_ACCOUNT` — restricts to regular user accounts,
excluding service accounts with atypical UAC values. Remove this restriction if
coverage of all account types is needed.

**Computers:**
```
(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$thresholdFileTime))
```

### Handling Accounts That Have Never Logged On

`lastLogonTimestamp` is `0` or absent for accounts that have never authenticated.
These are stale by definition. Include them by also running:

```
(&(objectClass=user)(!(lastLogonTimestamp=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

Merge results, setting `LastLogonTimestamp = $null` and `DaysSinceLastLogon = $null` for these.

### SearchRoot

If `-SearchBase` provided, set `$searcher.SearchRoot = [adsi]"LDAP://$SearchBase"`.

### Properties to Load

```
distinguishedName, sAMAccountName, userAccountControl,
lastLogonTimestamp, pwdLastSet, objectClass
```

### Output Schema

```powershell
[PSCustomObject]@{
    SamAccountName      = [string]
    DistinguishedName   = [string]
    ObjectType          = [string]   # 'User' | 'Computer'
    Enabled             = [bool]
    LastLogonTimestamp  = [DateTime] # $null if never logged on
    DaysSinceLastLogon  = [int]      # $null if never logged on
    PasswordLastSet     = [DateTime]
}
```

### Tests

```
Tests/Unit/AccountHygiene/Find-DSStaleAccounts.Tests.ps1
```

Mock two accounts: one with `lastLogonTimestamp` within threshold (excluded),
one beyond threshold (included). Verify `DaysSinceLastLogon` is computed correctly.
