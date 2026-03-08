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

---

## Compliance Mapping

This section maps each DirectoryServicesToolkit finding to the relevant controls
from **NIST SP 800-53 Rev 5**, **NIST SP 800-207** (Zero Trust Architecture),
and **CMMC Level 3** (NIST SP 800-172 + 800-171 practices).

Use this table to prioritise remediation for a specific compliance programme or
to generate evidence artefacts for an auditor.

### Abbreviations

| Abbreviation | Standard |
|--------------|----------|
| **800-53** | NIST SP 800-53 Rev 5 control identifier |
| **ZTA** | NIST SP 800-207 Zero Trust pillar — Identity (ID), Device (DV), Network (NW), Application (AP), Data (DA) |
| **CMMC** | CMMC Level 3 practice identifier (L2 = inherited from NIST 800-171; L3 = additional 800-172 practices) |

---

### Credential and Authentication Exposure

#### `Find-DSKerberoastable` — SPN accounts with crackable Kerberos hashes

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| IA-5(1) Authenticator Management — Password-Based Authentication | ID | L2: 3.5.7 (password complexity), 3.5.8 (history), 3.5.10 (cryptographic storage) |
| IA-5(2) PKI Authenticators | ID | L2: 3.5.3 (MFA) |
| AC-6 Least Privilege | ID | L2: 3.1.5 (least privilege) |
| SC-8 Transmission Confidentiality and Integrity | NW | L2: 3.13.8 (cryptographic protection in transit) |

**Threshold rationale:**
NIST 800-53 IA-5(1)(d) requires password change at defined intervals; IA-5(1)(g) bans re-use. The 90-day `High` threshold and 365-day `Critical` threshold align with the most common organisational maximum password age requirements. CMMC 3.5.7 requires passwords of sufficient complexity; service account passwords that have never rotated satisfy neither IA-5 nor 3.5.10 (cryptographic protection).

---

#### `Find-DSASREPRoastable` — Pre-authentication not required

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| IA-2 Identification and Authentication | ID | L2: 3.5.1 (identify and authenticate users) |
| IA-5(1) Password-Based Authentication | ID | L2: 3.5.7, 3.5.10 |
| SC-8 Transmission Confidentiality and Integrity | NW | L2: 3.13.8 |

**Threshold rationale:**
NIST 800-53 IA-2 requires all users to be uniquely identified and authenticated. Disabling Kerberos pre-authentication bypasses a fundamental authentication step, allowing any domain user to request an encrypted hash without presenting credentials — directly undermining IA-2 and CMMC 3.5.1.

---

#### `Find-DSGPPCredential` — Credentials in Group Policy Preferences XML

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| IA-5 Authenticator Management | ID | L2: 3.5.10 (cryptographically protected passwords) |
| SC-28 Protection of Information at Rest | DA | L2: 3.13.16 (protect CUI at rest) |
| CM-6 Configuration Settings | DV | L2: 3.4.2 (baseline configurations) |

**Threshold rationale:**
GPP credentials are encrypted with a known AES-256 key published by Microsoft (MS14-025). Any domain user can read SYSVOL. NIST 800-53 IA-5(6) prohibits writing authenticators to removable media or shared storage without protection; CMMC 3.5.10 prohibits plain-text credential storage.

---

### Privilege and Access Control

#### `Find-DSDelegation` — Kerberos delegation misconfigurations

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| AC-3 Access Enforcement | ID | L2: 3.1.1 (authorised access), 3.1.2 (transaction types) |
| AC-6 Least Privilege | ID | L2: 3.1.5 (least privilege) |
| IA-4 Identifier Management | ID | L2: 3.5.2 (authenticate devices) |
| SC-12 Cryptographic Key Establishment | NW | L3: 3.13.10e (key management) |

**Threshold rationale:**
Unconstrained delegation embeds full TGTs in service tickets, enabling any compromised service account or computer to impersonate any user domain-wide. NIST 800-53 AC-3 requires access enforcement to prevent such unbounded privilege escalation. CMMC 3.1.5 restricts least privilege; L3 3.13.10e addresses key establishment in privileged contexts.

---

#### `Find-DSInterestingACE` — Dangerous AD ACE entries

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| AC-2 Account Management | ID | L2: 3.1.1 (authorised access) |
| AC-3 Access Enforcement | ID | L2: 3.1.3 (control CUI flow) |
| AC-6 Least Privilege | ID | L2: 3.1.5 (least privilege) |
| AU-9 Protection of Audit Information | DA | L2: 3.3.1 (create and retain audit logs) |

**Threshold rationale:**
NIST 800-53 AC-6(1) prohibits granting privileged functions to non-privileged accounts. `WriteDACL` and `GenericAll` violate AC-3 by allowing a non-admin principal to rewrite the discretionary access control list, bypassing all downstream access enforcement. CMMC 3.1.5 directly requires least-privilege access.

---

#### `Find-DSADCSTemplateACL` — ESC4 write permissions on certificate templates

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| AC-3 Access Enforcement | ID | L2: 3.1.1, 3.1.3 |
| AC-6 Least Privilege | ID | L2: 3.1.5 |
| SC-17 Public Key Infrastructure Certificates | ID, NW | L2: 3.13.10 |

**Threshold rationale:**
SC-17 requires organisations to manage the PKI and control who may issue or modify certificates. Write access to a certificate template by non-admin principals violates AC-6 and SC-17 — it allows escalating a template to ESC1 (arbitrary SAN) without CA administrator rights.

---

#### `Get-DSAdminSDHolder` — Shadow admin (AdminCount=1 residual)

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| AC-2 Account Management | ID | L2: 3.1.1 |
| AC-6 Least Privilege | ID | L2: 3.1.5, 3.1.6 (non-privileged accounts for non-privileged functions) |
| AC-17 Remote Access | ID | L2: 3.1.12 |

**Threshold rationale:**
NIST 800-53 AC-2(3) requires disabling or removing inactive accounts; AC-2(7) requires role-based access management. Accounts retaining SDProp-managed DACLs after removal from protected groups are phantom privileged principals — an insider or attacker can reactivate them. CMMC 3.1.6 requires non-privileged accounts for non-privileged functions.

---

#### `Get-DSKeyCredLink` — Shadow Credentials (`msDS-KeyCredentialLink`)

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| IA-3 Device Identification and Authentication | DV | L2: 3.5.2 (authenticate devices) |
| AC-2 Account Management | ID | L2: 3.1.1 |
| SC-12 Cryptographic Key Establishment | NW | L3: 3.13.10e |

**Threshold rationale:**
An attacker with write access to `msDS-KeyCredentialLink` can add their own key credential and authenticate as any machine account via PKINIT without knowledge of the machine account password. NIST 800-53 IA-3 requires device authentication; SC-12 requires controlled key establishment. CMMC L3 3.13.10e requires key management practices that would detect or prevent unauthorised key injection.

---

### AD Certificate Services (PKI)

#### `Find-DSADCSTemplate` — ESC1/ESC2/ESC3 vulnerable templates

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| SC-17 Public Key Infrastructure Certificates | ID, NW | L2: 3.13.10 |
| IA-5(2) PKI Authenticators | ID | L2: 3.5.3 (MFA) |
| AC-3 Access Enforcement | ID | L2: 3.1.1 |
| CM-6 Configuration Settings | DV | L2: 3.4.2 |

**Threshold rationale:**
NIST 800-53 SC-17 requires organisations to obtain PKI certificates from approved CAs and to ensure certificates are issued in accordance with policy. Templates that allow enrollees to supply arbitrary Subject Alternative Names (ESC1) violate SC-17 by enabling certificate fraud. CMMC 3.13.10 requires managing cryptographic keys; an exploitable template undermines that key management.

---

#### `Get-DSADCSAuthority` — ESC8 HTTP enrollment and certificate expiry

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| SC-8 Transmission Confidentiality and Integrity | NW | L2: 3.13.8 |
| SC-17 Public Key Infrastructure Certificates | ID, NW | L2: 3.13.10 |
| IA-8 Identification and Authentication (Non-Org Users) | ID | L2: 3.5.1 |

**Threshold rationale:**
HTTP-only CA enrollment endpoints accept NTLM authentication and are vulnerable to NTLM relay (ESC8). NIST 800-53 SC-8 requires encryption in transit for all sensitive communications; SC-8(1) mandates cryptographic protection. CMMC 3.13.8 requires cryptographic mechanisms to prevent unauthorised disclosure or modification in transit.

---

#### `Test-DSADCSCAFlags` — ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 on CA

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| SC-17 Public Key Infrastructure Certificates | ID, NW | L2: 3.13.10 |
| CM-6 Configuration Settings | DV | L2: 3.4.2 (establish and document baseline configurations) |
| CM-7 Least Functionality | DV | L2: 3.4.6 (permit only essential capabilities) |

**Threshold rationale:**
`EDITF_ATTRIBUTESUBJECTALTNAME2` allows a caller to specify a SAN in any certificate request, regardless of template configuration. This is a CA-wide flag that undermines the entire template access control model. NIST 800-53 CM-7 requires disabling unnecessary functions; SC-17 requires adherence to PKI certificate policy.

---

### Network Protocol Security

#### `Test-DSSMBSigning` — SMB signing enforcement

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| SC-8 Transmission Confidentiality and Integrity | NW | L2: 3.13.8 (cryptographic mechanisms in transit) |
| SC-8(1) Cryptographic Protection | NW | L2: 3.13.8 |
| IA-3 Device Identification and Authentication | DV | L2: 3.5.2 |
| CM-6 Configuration Settings | DV | L2: 3.4.2 |

**Threshold rationale:**
NIST 800-53 SC-8 requires confidentiality and integrity protection for all information in transit. SMB without required signing allows NTLM relay attacks: an intercepted SMB authentication can be replayed to other services. CMMC 3.13.8 requires cryptographic mechanisms to prevent unauthorised disclosure during transmission. NIST 800-207 (ZTA) Network pillar requires all traffic to be authenticated and, where possible, encrypted regardless of network location.

**NIST 800-207 (ZTA) note:** SMB signing directly satisfies the ZTA principle that all traffic must be authenticated at the session layer, independent of network location (perimeter). A DC without required SMB signing violates ZTA's Device and Network pillars — an on-network attacker with relay capability can act as an authenticated device.

---

#### `Test-DSLDAPSigning` and `Test-DSLDAPChannelBinding` — LDAP integrity

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| SC-8 Transmission Confidentiality and Integrity | NW | L2: 3.13.8 |
| SC-8(1) Cryptographic Protection | NW | L2: 3.13.8 |
| IA-3 Device Identification and Authentication | DV | L2: 3.5.2 |
| IA-8 Identification and Authentication (Non-Org Users) | ID | L2: 3.5.1 |

**Threshold rationale:**
LDAP signing (RequireSigning) prevents LDAP relay by requiring Kerberos or NTLM session signing. LDAP channel binding ties the LDAP session to the TLS channel, blocking relay from TLS-downgrade attacks. NIST 800-53 SC-8(1) and CMMC 3.13.8 both require cryptographic protection of data in transit to the directory. Microsoft Security Advisory ADV190023 classifies LDAP signing as a mandatory security baseline.

**NIST 800-207 (ZTA) note:** The ZTA Network pillar requires all sessions to be authenticated and integrity-protected. Unsigned LDAP violates this principle by allowing a man-in-the-middle to inject or read directory data without detection.

---

#### `Get-DSNTLMPolicy` and `Find-DSNTLMRestrictions` — NTLM hardening

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| IA-2 Identification and Authentication | ID | L2: 3.5.1 |
| SC-8 Transmission Confidentiality and Integrity | NW | L2: 3.13.8 |
| CM-6 Configuration Settings | DV | L2: 3.4.2 |
| SI-2 Flaw Remediation | DV | L2: 3.14.1 (identify, report, correct flaws) |

**Threshold rationale:**
NTLM is a challenge-response protocol susceptible to relay, pass-the-hash, and offline cracking. NIST 800-53 IA-2 requires authenticated sessions with assurance properties that NTLM does not provide for high-assurance systems. CMMC L3 practices from NIST 800-172 section 3.5 require replay-resistant authentication (IA.L3-3.5.4e), which Kerberos satisfies but NTLM does not.

**NIST 800-207 (ZTA) note:** ZTA Identity pillar requires strong, replay-resistant authentication. NTLM restrictions enforce the ZTA requirement that no implicit trust is granted based on network location — forcing Kerberos authentication ensures mutual authentication between client and server.

---

### Account Hygiene and Password Controls

#### `Get-DSPasswordPolicy` — Domain and fine-grained password policy

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| IA-5(1) Password-Based Authentication | ID | L2: 3.5.7 (complexity), 3.5.8 (history), 3.5.9 (temp passwords), 3.5.10 (cryptographic storage) |
| AC-7 Unsuccessful Logon Attempts | ID | L2: 3.1.8 (limit login attempts) |
| CM-6 Configuration Settings | DV | L2: 3.4.2 |

**Threshold rationale:**

| Policy attribute | NIST 800-53 IA-5(1) requirement | CMMC 3.5.7 minimum | This toolkit threshold |
|------------------|---------------------------------|-------------------|----------------------|
| Minimum length | ≥ 8 characters for moderate impact; ≥ 15 for high impact | Sufficient complexity and length | < 8 → `Critical`; 8–11 → `High` |
| Complexity | Required | Required | Disabled → `Critical` |
| History | Minimum 24 (800-53); minimum 5 (800-171) | ≥ 5 (800-171 3.5.8) | < 12 → `High` |
| Lockout threshold | Required (800-53 AC-7) | Required (800-171 3.1.8) | 0 → `High` |
| Reversible encryption | Prohibited | Prohibited (3.5.10) | Enabled → `Critical` |

---

#### `Find-DSStaleAccounts` — Inactive user and computer accounts

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| AC-2 Account Management | ID | L2: 3.1.1 |
| AC-2(3) Disable Inactive Accounts | ID | L2: 3.1.1 (authorised access only) |
| IA-4 Identifier Management | ID | L2: 3.5.2 |

**Threshold rationale:**
NIST 800-53 AC-2(3) requires disabling accounts that have been inactive for a defined period. The 90-day default and 365-day elevated threshold reflect common organisational baselines. CMMC 3.1.1 restricts system access to authorised users; stale accounts with unrevoked access violate this control. CMMC L3 3.5.6e (NIST 800-172) requires disabling accounts within 24 hours after an employee departs.

---

#### `Find-DSStalePrivilegedAccounts` — Disabled accounts in privileged groups

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| AC-2 Account Management | ID | L2: 3.1.1 |
| AC-2(3) Disable Inactive Accounts | ID | L2: 3.1.1 |
| AC-6 Least Privilege | ID | L2: 3.1.5, 3.1.6 |
| AC-2(7) Role-Based Schemes | ID | L2: 3.1.5 |

**Threshold rationale:**
A disabled account that remains a member of Domain Admins or Enterprise Admins can be re-enabled by an attacker with write access to the account object. NIST 800-53 AC-2(7) requires role-based account management; AC-6(1) prohibits granting privileged access beyond what is required. CMMC 3.1.6 requires non-privileged accounts for non-privileged functions; stale privileged memberships violate this regardless of account-enabled status.

---

#### `Find-DSPasswordNeverExpires` — Non-expiring passwords

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| IA-5(1)(d) Authenticator Lifecycle | ID | L2: 3.5.7, 3.5.8 |
| AC-6 Least Privilege | ID | L2: 3.1.5 |

**Threshold rationale:**
NIST 800-53 IA-5(1)(d) requires changing/revoking authenticators at specified intervals. Accounts with `DONT_EXPIRE_PASSWORD` bypass the domain password age policy. For Kerberoastable accounts (`HasSPN = $true`), a stale non-expiring password hash has indefinite cracking window, raising the risk to `High`.

---

#### `Find-DSPasswordNotRequired` — PASSWD_NOTREQD flag

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| IA-5 Authenticator Management | ID | L2: 3.5.7, 3.5.10 |
| IA-2 Identification and Authentication | ID | L2: 3.5.1 |

**Threshold rationale:**
`PASSWD_NOTREQD` allows an account to authenticate with a blank password if no Fine-Grained Password Policy applies. NIST 800-53 IA-5 requires all accounts to have authenticators meeting minimum standards; IA-2 requires authentication. CMMC 3.5.10 prohibits plain-text or blank passwords for any account.

---

### Trust and Forest Boundaries

#### `Get-DSTrustRelationship` — AD trust SID filtering and delegation

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| AC-3 Access Enforcement | ID | L2: 3.1.1, 3.1.3 |
| AC-4 Information Flow Enforcement | NW | L2: 3.1.3 (control CUI flow) |
| IA-8 Identification and Authentication (Non-Org Users) | ID | L2: 3.5.1 |
| SC-7 Boundary Protection | NW | L2: 3.13.1 (monitor, control, and protect communications at external boundaries) |

**Threshold rationale:**
SID history allows principals from a trusted domain to carry SIDs from the trusting domain. Without SID filtering, an attacker who compromises any principal in the trusted domain can inject Domain Admin SIDs and escalate. NIST 800-53 AC-4 requires information-flow enforcement across organisational boundaries; SC-7 requires boundary protection. CMMC 3.13.1 requires boundary protection at external connections; cross-forest trusts without SID filtering extend an internal attack surface to external forests.

**NIST 800-207 (ZTA) note:** ZTA rejects implicit trust based on network location or trust relationships. Cross-forest trusts with no SID filtering represent exactly the kind of implicit, network-location-based trust that ZTA Architecture (Section 2) explicitly disallows. Zero Trust requires per-session, per-request authentication and authorisation regardless of trust relationships.

---

### DNS Security

#### `Find-DSADIDNSRecord` — ADIDNS write access and wildcard records

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| SC-20 Secure Name/Address Resolution Service (Authoritative Source) | NW | L2: 3.13.1 |
| SC-21 Secure Name/Address Resolution Service (Recursive Resolver) | NW | L2: 3.13.1 |
| AC-3 Access Enforcement | ID | L2: 3.1.1 |
| SI-3 Malicious Code Protection | DV | L2: 3.14.2 |

**Threshold rationale:**
NIST 800-53 SC-20 requires that authoritative name servers implement DNSSEC or equivalent controls. Wildcard records in ADIDNS allow any domain-joined machine to intercept unresolved DNS queries — a DNS poisoning/WPAD attack vector. SC-20/SC-21 require integrity of name resolution; CMMC 3.13.1 requires communications boundary protection.

---

#### `Test-DSDNSSecurity` — Zone transfer and unsecured dynamic updates

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| SC-20 Secure Name/Address Resolution | NW | L2: 3.13.1 |
| CM-7 Least Functionality | DV | L2: 3.4.6 |
| AC-3 Access Enforcement | ID | L2: 3.1.1 |

**Threshold rationale:**
Zone transfers to any requestor expose the complete DNS topology — IP assignments, host names, and domain structure — enabling targeted reconnaissance. NIST 800-53 CM-7 requires disabling unnecessary capabilities; SC-20 requires authenticated zone transfers. Unsecured dynamic updates allow unauthenticated DNS injection, enabling WPAD and relay attacks.

---

### Domain Controller Configuration

#### `Find-DSCoercionSurface` and `Test-DSPrintSpooler` — Print Spooler coercion

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| CM-7 Least Functionality | DV | L2: 3.4.6 (permit only essential capabilities) |
| CM-11 User-Installed Software | DV | L2: 3.4.9 (control installation) |
| SI-2 Flaw Remediation | DV | L2: 3.14.1 |
| AC-6 Least Privilege | ID | L2: 3.1.5 |

**Threshold rationale:**
The Print Spooler service exposes `MS-RPRN` coercion primitives (`RpcRemoteFindFirstPrinterChangeNotification`), enabling any authenticated domain user to force a DC to authenticate outbound. NIST 800-53 CM-7 requires disabling all services not required for system function. Microsoft's own security baseline disables the Print Spooler on DCs. CMMC 3.4.6 requires permitting only essential capabilities on CUI systems.

---

#### `Test-DSLDAPChannelBinding` — LDAP channel binding (ADV190023)

See [`Test-DSLDAPSigning`](#test-dsldapsigning-and-test-dsldapchannelbinding--ldap-integrity) above.

---

#### `Get-DSReplicationStatus` — AD replication health

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| SI-2 Flaw Remediation | DV | L2: 3.14.1 |
| CP-9 Information System Backup | DA | L2: 3.8.9 (protect backups of CUI) |
| CP-10 Recovery and Reconstitution | DA | L2: 3.6.1 (incident handling) |

**Threshold rationale:**
Sustained AD replication failure causes domain divergence: DCs hold inconsistent copies of the directory, leading to authentication failures and policy inconsistencies. NIST 800-53 SI-2 requires identifying and correcting flaws. Five or more consecutive failures (`Critical`) indicate the USN rollback or USN lingering object condition, which may require authoritative restore.

---

#### `Get-DSSysvolHealth` — SYSVOL/NETLOGON replication

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| CM-6 Configuration Settings | DV | L2: 3.4.2 |
| SI-6 Security Function Verification | DV | L3: 3.14.3e (identify, report, correct security functions) |

**Threshold rationale:**
SYSVOL hosts Group Policy templates and logon scripts. An unhealthy SYSVOL means security policy (AppLocker, audit policy, LAPS, etc.) is not consistently applied across the domain. NIST 800-53 CM-6 requires defined, documented, and enforced configuration settings; a split SYSVOL defeats CM-6 enforcement.

---

#### `Get-OSLevelDomainController` — DC operating system version coverage

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| SI-2 Flaw Remediation | DV | L2: 3.14.1 (identify/correct flaws promptly) |
| CM-2 Baseline Configuration | DV | L2: 3.4.1 (establish baseline configurations) |
| SA-22 Unsupported System Components | DV | L2: 3.14.1 |

**Threshold rationale:**
DCs running end-of-life operating systems no longer receive security patches. NIST 800-53 SA-22 requires replacing components that are no longer supported by the vendor. The 75%/50% thresholds reflect the practical risk of a mixed OS environment where a substantial fraction of DCs lack current security patches.

---

### TPM and Hardware Security

#### `Test-IfxTPM` — Infineon TPM ROCA vulnerability (CVE-2017-15361)

| 800-53 | ZTA Pillar | CMMC |
|--------|-----------|------|
| SC-17 Public Key Infrastructure Certificates | ID, NW | L2: 3.13.10 |
| SC-12 Cryptographic Key Establishment | NW | L3: 3.13.10e |
| SI-2 Flaw Remediation | DV | L2: 3.14.1 |

**Threshold rationale:**
CVE-2017-15361 allows RSA private keys generated by vulnerable Infineon firmware to be reconstructed from the public key. If the TPM is used for BitLocker sealing, device authentication, or ADCS key attestation, the private key material is compromised. NIST 800-53 SC-12 requires secure key establishment; SC-17 requires PKI certificate management practices that would detect or prevent use of weak keys. CMMC 3.13.10e requires managing cryptographic keys per FIPS guidelines.

---

## NIST 800-207 Zero Trust Architecture — Pillar Summary

NIST SP 800-207 defines five logical components (pillars) that a Zero Trust Architecture
must address. The table below maps each toolkit function to the primary ZTA pillar(s) it
validates:

| ZTA Pillar | Validated by |
|------------|-------------|
| **Identity** — Every user/service must be strongly authenticated and continuously validated | `Find-DSKerberoastable`, `Find-DSASREPRoastable`, `Find-DSDelegation`, `Find-DSInterestingACE`, `Get-DSAdminSDHolder`, `Get-DSKeyCredLink`, `Get-DSPasswordPolicy`, `Find-DSPasswordNeverExpires`, `Find-DSPasswordNotRequired`, `Find-DSGPPCredential`, `Get-DSTrustRelationship`, `Get-DSNTLMPolicy` |
| **Device** — Only managed and compliant devices may access resources | `Test-IfxTPM`, `Get-DSLAPSCoverage`, `Test-DSPrintSpooler`, `Find-DSCoercionSurface`, `Get-OSLevelDomainController`, `Get-DSSysvolHealth` |
| **Network/Environment** — Assume the network is hostile; protect all sessions | `Test-DSSMBSigning`, `Test-DSLDAPSigning`, `Test-DSLDAPChannelBinding`, `Test-DSDNSSecurity`, `Find-DSADIDNSRecord`, `Find-StaleDNSDomainRecord`, `Get-DSNTLMPolicy`, `Find-DSNTLMRestrictions` |
| **Application Workload** — Applications must authenticate and authorise each request | `Get-DSADCSAuthority`, `Find-DSADCSTemplate`, `Find-DSADCSTemplateACL`, `Test-DSADCSCAFlags`, `Find-DSADCSWebEnrollment`, `Find-DSADCSEnrollmentAgents` |
| **Data** — Data is protected regardless of where it resides or travels | `Find-DSBitlockerKey`, `Get-DSLAPSCoverage`, `Find-DSGPPCredential` |

---

## CMMC Level 3 — Applicable Practice Coverage

CMMC Level 3 (NIST SP 800-172) adds 24 practices above the CMMC Level 2 baseline (NIST
SP 800-171). The table below lists the Level 3-specific practices relevant to Active
Directory security assessments:

| CMMC L3 Practice | NIST 800-172 Source | Relevant Functions |
|------------------|--------------------|--------------------|
| **AC.L3-3.1.3e** — Control CUI flow across security domains using policy-based controls | 3.1.3e | `Get-DSTrustRelationship`, `Find-DSInterestingACE` |
| **IA.L3-3.5.3e** — Employ multi-factor authentication for local and network access | 3.5.3e | `Get-DSNTLMPolicy`, `Test-DSLDAPSigning` (enforcing Kerberos/NTLM policy) |
| **IA.L3-3.5.4e** — Employ replay-resistant authentication | 3.5.4e | `Test-DSSMBSigning`, `Test-DSLDAPSigning`, `Test-DSLDAPChannelBinding`, `Get-DSNTLMPolicy` |
| **IA.L3-3.5.5e** — Use prohibit temporary accounts within 72 hours | 3.5.5e | `Find-DSStaleAccounts` |
| **IA.L3-3.5.6e** — Disable accounts within 24 hours after termination | 3.5.6e | `Find-DSStaleAccounts`, `Find-DSStalePrivilegedAccounts` |
| **SC.L3-3.13.10e** — Establish and manage cryptographic keys for all employed cryptographic functions | 3.13.10e | `Test-DSADCSCAFlags`, `Find-DSADCSTemplateACL`, `Get-DSKeyCredLink`, `Test-IfxTPM` |
| **SI.L3-3.14.3e** — Employ penetration testing — periodic red team exercises | 3.14.3e | (entire toolkit supports this practice) |

---

## Compliance-Filtered Reporting Examples

### CMMC Level 2 Gap Report (NIST 800-171 baseline)

```powershell
# Collect findings relevant to CMMC L2 password controls (3.5.x)
$credFindings = @(
    Find-DSKerberoastable
    Find-DSASREPRoastable
    Find-DSPasswordNeverExpires
    Find-DSPasswordNotRequired
    (Get-DSPasswordPolicy)
)
$credFindings | Where-Object { $_.RiskLevel -in 'Critical','High' } |
    Select-Object RiskLevel, SamAccountName, PolicyType, Finding |
    Sort-Object RiskLevel

# CMMC L2 3.4.x — Configuration management findings
$cmFindings = @(
    Test-DSSMBSigning
    Test-DSLDAPSigning
    Test-DSLDAPChannelBinding
    Test-DSADCSCAFlags
    Find-DSCoercionSurface
)
$cmFindings | Where-Object { $_.RiskLevel -in 'Critical','High' }
```

### NIST 800-53 High-Baseline SC Control Validation

```powershell
# SC-8 Transmission Confidentiality and Integrity
$sc8 = @(Test-DSSMBSigning; Test-DSLDAPSigning; Test-DSLDAPChannelBinding)
$sc8 | Select-Object Hostname, DCName, RiskLevel, @{N='Control';E={'SC-8'}}

# SC-17 PKI Certificate Management
$sc17 = @(
    Find-DSADCSTemplate
    Get-DSADCSAuthority
    Find-DSADCSTemplateACL
    Test-DSADCSCAFlags
)
$sc17 | Where-Object { $_.RiskLevel -in 'Critical','High' } |
    Select-Object RiskLevel, TemplateName, CAName, Finding
```

### NIST 800-207 Zero Trust — Identity Pillar Validation

```powershell
# Validate Zero Trust Identity pillar controls
$zta_id = @(
    Find-DSKerberoastable
    Find-DSASREPRoastable
    Find-DSDelegation
    Find-DSInterestingACE
    Get-DSAdminSDHolder
    Get-DSKeyCredLink
    Get-DSPasswordPolicy
    Get-DSTrustRelationship
    Get-DSNTLMPolicy
)
$zta_id | Where-Object { $_.RiskLevel -in 'Critical','High' } |
    Group-Object RiskLevel | Select-Object Name, Count
```
