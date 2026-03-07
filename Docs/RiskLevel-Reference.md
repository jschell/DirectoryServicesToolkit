# RiskLevel Property Reference

This document describes how the `RiskLevel` property is calculated across all
DirectoryServicesToolkit functions that produce it. Every function that returns
security-relevant findings includes a `RiskLevel` string property in its output
objects to enable consistent cross-function pipeline filtering:

```powershell
# Filter any function's output to high-severity findings
Find-DSKerberoastable | Where-Object { $_.RiskLevel -in 'Critical','High' }
```

---

## RiskLevel Scale

| Value           | Meaning |
|-----------------|---------|
| `Critical`      | Directly exploitable, immediate domain compromise path, or active attack indicator. Remediate within 24 hours. |
| `High`          | Significantly elevated attack surface. Requires prompt remediation. |
| `Medium`        | Elevated risk requiring an attacker to chain additional conditions. Remediate within normal patch cadence. |
| `Low`           | Compliant or healthy state; no immediate action required. |
| `Informational` | Present but not a vulnerability by itself; provides context for the assessor. |
| `Unknown`       | Data could not be collected (connectivity failure, access denied, etc.). Treat as unverified. |

---

## Function-by-Function Breakdown

### Security

#### `Find-DSKerberoastable`

**Source fields:** `IsManagedAccount`, `PasswordAgeDays`

| Condition | RiskLevel |
|-----------|-----------|
| `IsManagedAccount = $true` | `Low` — auto-rotated 120-char password, not practically crackable |
| `PasswordAgeDays = $null` (never set) | `High` — unknown credential age |
| `PasswordAgeDays >= 365` | `Critical` — very old hash, high cracking probability |
| `PasswordAgeDays >= 90` | `High` |
| `PasswordAgeDays < 90` | `Medium` |

---

#### `Find-DSASREPRoastable`

**Source fields:** `Enabled`

| Condition | RiskLevel |
|-----------|-----------|
| Account is enabled | `High` — AS-REP hash requestable without any credentials |
| Account is disabled | `Low` — flag exists but account cannot authenticate |

---

#### `Find-DSDelegation`

**Source fields:** `DelegationType`, `ProtocolTransition`

| Condition | RiskLevel |
|-----------|-----------|
| `DelegationType = 'Unconstrained'` (users or computers) | `Critical` — KDC embeds full TGT in service tickets; any service on the host can harvest credentials |
| `DelegationType = 'Constrained'` with `ProtocolTransition = $true` | `High` — S4U2Self allows impersonating any user without a forwarded TGT |
| `DelegationType = 'Constrained'` with `ProtocolTransition = $false` | `Medium` — narrower scope; requires user's TGS |
| `DelegationType = 'RBCD'` | `Medium` — requires attacker to already control an account with an SPN |

---

#### `Find-DSInterestingACE`

**Source fields:** `Right`

| Right | RiskLevel |
|-------|-----------|
| `GenericAll` | `Critical` — full control over the target object |
| `WriteDACL` | `Critical` — DACL rewrite; can grant any right to any principal |
| `WriteOwner` | `High` — owner can modify DACL to grant arbitrary rights |
| `GenericWrite` | `High` — write to any unprotected attribute |
| `AllExtendedRights` | `High` — includes `GetChanges`/`GetChangesAll` (DCSync), `ForceChangePassword`, etc. |
| `ForceChangePassword` | `High` — reset password without knowing the current one |
| Other flagged rights | `Medium` |

---

#### `Find-DSADCSTemplate`

**Source fields:** `IsVulnerable`, `ESCFlags` (`EnrolleeSuppliesSubject`, `AnyPurposeEKU`, `NoRASignatureRequired`)

| Condition | RiskLevel |
|-----------|-----------|
| `IsVulnerable = $false` (manager approval mitigates) | `Informational` |
| `IsVulnerable = $true` and `ESC1` set (`EnrolleeSuppliesSubject`) | `Critical` — arbitrary principal impersonation via SAN |
| `IsVulnerable = $true` and `ESC2` set (`AnyPurposeEKU`) | `High` — template usable for any authentication purpose |
| `IsVulnerable = $true`, only `ESC3-Condition` set | `Medium` — missing RA signature is a prerequisite, not a standalone exploit |

---

#### `Get-DSADCSAuthority`

**Source fields:** `HTTPEndpointCount`, `CertificateExpiry`

| Condition | RiskLevel |
|-----------|-----------|
| `HTTPEndpointCount > 0` | `Critical` — HTTP enrollment exposes NTLM relay attack surface (ESC8) |
| Certificate expires within 30 days | `High` — operational disruption to authentication for all relying services |
| Otherwise | `Informational` |

---

#### `Test-IfxTPM`

**Source fields:** `VulnFirmware`, `InfineonTPM`, `Error`

| Condition | RiskLevel |
|-----------|-----------|
| Query returned an error | `Unknown` |
| `VulnFirmware = $true` | `High` — CVE-2017-15361 (ROCA): RSA private key can be reconstructed from public key alone |
| `InfineonTPM = $true` but firmware not in vulnerable range | `Low` |
| Non-Infineon TPM | `Informational` |

---

### DNS

#### `Find-DSADIDNSRecord`

**Source fields:** `FindingType`, `Right`

| Condition | RiskLevel |
|-----------|-----------|
| `FindingType = 'WildcardRecord'` | `Critical` — wildcard `dnsNode` intercepts all unresolved queries; active attack indicator |
| `FindingType = 'UnexpectedWriteAccess'` and `Right = 'GenericAll'` | `Critical` |
| `FindingType = 'UnexpectedWriteAccess'` (other rights) | `High` — non-privileged principals can inject DNS records, enabling relay/WPAD attacks |

---

#### `Find-StaleDNSDomainRecord`

**Source fields:** `ComputerName` (stale sentinel value)

| Condition | RiskLevel |
|-----------|-----------|
| Record resolves to a known active DC | `Informational` |
| Record does not match any active DC (`!--STALE ENTRY--!`) | `Medium` — orphaned IP can be registered to hijack domain authentication traffic |

---

#### `Test-DSDNSSecurity`

**Source fields:** `AllowsUnsecuredDynamic`, `ZoneTransferEnabled`, `ZoneTransferPolicy`

| Condition | RiskLevel |
|-----------|-----------|
| `ZoneTransferPolicy = 'ToAny'` AND `AllowsUnsecuredDynamic = $true` | `Critical` |
| `ZoneTransferPolicy = 'ToAny'` | `High` — full zone contents exposed to any requestor |
| `AllowsUnsecuredDynamic = $true` | `High` — unauthenticated clients can register arbitrary DNS records |
| `ZoneTransferEnabled = $true` (restricted to list/NS servers) | `Medium` |
| No risk factors | `Low` |

---

### Domain Controllers

#### `Find-DSCoercionSurface`

**Source fields:** `CompositeRisk` (mirrored to `RiskLevel`)

`CompositeRisk` / `RiskLevel` is computed from `SpoolerRunning` and `IsDomainController`:

| Condition | RiskLevel |
|-----------|-----------|
| DC with Print Spooler running | `Critical` — Spooler coercion captures TGTs via DC unconstrained delegation |
| Non-DC with Print Spooler running | `High` |
| DC without Spooler (unconstrained delegation inherent to DCs) | `High` |
| Non-DC with unconstrained delegation, no Spooler | `Medium` |

---

#### `Get-DSSysvolHealth`

**Source fields:** `IsHealthy`

| Condition | RiskLevel |
|-----------|-----------|
| `IsHealthy = $true` | `Low` |
| `IsHealthy = $false` or DC unreachable | `High` — Group Policy not distributing; inconsistent security policy across domain |

---

#### `Get-DSReplicationStatus`

**Source fields:** `IsFailing`, `ConsecutiveFailures`

| Condition | RiskLevel |
|-----------|-----------|
| `IsFailing = $false` | `Low` |
| `IsFailing = $true` and `ConsecutiveFailures >= 5` | `Critical` — extended replication failure causing significant directory divergence |
| `IsFailing = $true` and `ConsecutiveFailures < 5` | `High` |

---

#### `Find-DSNTLMRestrictions`

**Source fields:** N/A (presence indicates positive control)

Each result row represents an NTLM restriction setting found in a GPO. `RiskLevel = 'Informational'` for all rows. **The absence of any results** (empty output) is the actual risk indicator — it means no NTLM hardening policy is enforced via Group Policy.

---

#### `Get-OSLevelDomainController`

**Source fields:** `osCoverage` (computed ratio)

| Condition | RiskLevel |
|-----------|-----------|
| Coverage >= 75% | `Low` |
| Coverage 50–74% | `Medium` |
| Coverage < 50% | `High` — majority of DCs running below target OS level; increased patch exposure |

---

### Account Hygiene

#### `Get-DSPasswordPolicy`

Applies to both `Default` and `FineGrained` policy types.

**Source fields:** `ReversibleEncryption`, `ComplexityEnabled`, `MinPasswordLength`, `PasswordHistoryCount`, `LockoutThreshold`

| Condition | RiskLevel |
|-----------|-----------|
| `ReversibleEncryption = $true` | `Critical` — passwords stored reversibly, recoverable as plaintext |
| `ComplexityEnabled = $false` AND `MinPasswordLength < 8` | `Critical` |
| Any single: no complexity, length < 8, history < 12, lockout threshold = 0 | `High` |
| All attributes meet minimum thresholds | `Low` |

Minimum thresholds used: complexity required, min length ≥ 8, history ≥ 12, lockout threshold ≠ 0.

---

#### `Find-DSStaleAccounts`

**Source fields:** `DaysSinceLastLogon`

| Condition | RiskLevel |
|-----------|-----------|
| `DaysSinceLastLogon = $null` (never logged on) | `High` — credentials may never have been rotated; account is likely orphaned |
| `DaysSinceLastLogon >= 365` | `High` |
| `DaysSinceLastLogon < 365` (but above threshold) | `Medium` |

---

#### `Find-DSPasswordNeverExpires`

**Source fields:** `HasSPN`

| Condition | RiskLevel |
|-----------|-----------|
| `HasSPN = $true` | `High` — Kerberoastable account with no expiry deadline on its password hash |
| `HasSPN = $false` | `Medium` — non-expiring passwords accumulate age but are not Kerberoastable |

---

#### `Find-DSPasswordNotRequired`

**Source fields:** `Enabled`

| Condition | RiskLevel |
|-----------|-----------|
| Account is enabled | `High` — PASSWD_NOTREQD flag allows blank-password authentication when no FGPP applies |
| Account is disabled | `Low` — flag present but account cannot be exploited |

---

### Trusts

#### `Get-DSTrustRelationship`

**Source fields:** `SIDFilteringEnabled`, `ForestTransitive`, `Direction`, `IsTransitive`, `TGTDelegationBlocked`

| Condition | RiskLevel |
|-----------|-----------|
| `SIDFilteringEnabled = $false` AND (`ForestTransitive = $true` OR `Direction = 'Bidirectional'`) | `Critical` — SID history attack path with broad scope; attacker in trusted domain can escalate to DA/EA |
| `SIDFilteringEnabled = $false` | `High` — SID history attack; narrower unidirectional scope |
| `IsTransitive = $true` AND `TGTDelegationBlocked = $false` | `High` — unconstrained delegation propagates across trust boundary |
| Otherwise | `Informational` — trust relationships are expected in multi-domain forests |

---

### Enumeration

#### `Get-DSAdminSDHolder`

**Source fields:** `IsCurrentProtectedMember`

| Condition | RiskLevel |
|-----------|-----------|
| `IsCurrentProtectedMember = $false` | `High` — AdminCount=1 residual; account has SDProp-managed DACL but is not in any protected group; potential shadow admin |
| `IsCurrentProtectedMember = $true` | `Informational` — expected state for active protected group members |

---

#### `Get-DSKeyCredLink`

**Source fields:** `MachineType` (all entries)

All results are `RiskLevel = 'High'`. Any non-DC computer with `msDS-KeyCredentialLink` populated may indicate a Shadow Credentials attack: an attacker with write access to this attribute can add their own key credential and authenticate as the machine account via PKINIT.

---

## Functions Without RiskLevel

The following functions return data that is contextual, reference, or utility in
nature. They do not include a `RiskLevel` property because they are not designed
to surface individual security findings:

| Function | Reason |
|----------|--------|
| `ConvertFrom-TrustAttributeValue` | Pure bitmask-to-name converter; returns `OrderedDictionary` |
| `ConvertTo-Guid` | Pure type converter |
| `Find-DSBitlockerKey` | Key validity check utility; returns plaintext recovery key — not a finding |
| `Get-DSDomainObjects` | Generic LDAP query; caller interprets results |
| `Get-DSComputerByProperty` | Generic query; caller interprets results |
| `Get-DSUserByProperty` | Generic query; caller interprets results |
| `Get-DSAdminAccounts` | Enumerates privileged accounts; informational catalog |
| `Get-DSServiceAccounts` | Service account discovery; informational catalog |
| `Get-DSGPO` | GPO inventory; no per-GPO security verdict |
| `Get-DSSelectiveAuth` | Selective Authentication enumeration; informational |
| `Get-DSResponseTime` | Network latency measurement; not a security finding |
| `Get-LastLoginInDomain` | Per-DC last logon lookup; raw data lookup |
| `Get-TPMDetail` | Raw TPM WMI data; use `Test-IfxTPM` for risk assessment |
| `New-KerberosTicketRequest` | Ticket request utility |

---

## Cross-Function Risk Aggregation

To get a domain-wide critical/high finding summary across multiple functions:

```powershell
$findings = @(
    Find-DSKerberoastable
    Find-DSASREPRoastable
    Find-DSDelegation
    Find-DSInterestingACE
    Find-DSADCSTemplate
    Get-DSADCSAuthority
    Find-DSGPPCredential
    Find-DSADCSWebEnrollment
    Test-DSSMBSigning
    Test-DSLDAPSigning
    Test-DSLDAPChannelBinding
    Find-DSPasswordNotRequired
    Get-DSTrustRelationship
    Get-DSAdminSDHolder
    Get-DSKeyCredLink
)

$findings | Where-Object { $_.RiskLevel -in 'Critical','High' } |
    Select-Object RiskLevel, @{N='Object'; E={ $_.SamAccountName ?? $_.Name ?? $_.Hostname ?? $_.ZoneName ?? $_.TargetObject ?? $_.DCName }} |
    Sort-Object RiskLevel, Object
```

> **Note:** Functions that already have a composite risk property (`Test-DSLDAPSecurity` →
> `CompositeRiskLevel`; `Find-DSCoercionSurface` → `CompositeRisk`) expose that value
> as `RiskLevel` for pipeline uniformity.
