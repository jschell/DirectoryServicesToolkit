# DirectoryServicesToolkit

A PowerShell module for Active Directory security assessment. Functions enumerate attack surface, evaluate misconfigurations, and produce structured output suitable for reporting pipelines — without requiring RSAT or the `ActiveDirectory` module.

---

## Requirements

| Dependency | Version | Install |
|---|---|---|
| PowerShell | 7.4+ | [github.com/PowerShell/PowerShell](https://github.com/PowerShell/PowerShell) |
| Pester | 5.x | `Install-PSResource Pester -Scope CurrentUser` |
| PSScriptAnalyzer | 1.21+ | `Install-PSResource PSScriptAnalyzer -Scope CurrentUser` |
| InvokeBuild | any | `Install-PSResource InvokeBuild -Scope CurrentUser` |

Domain connectivity is required for most functions. Read access to the domain partition is the minimum permission level; specific functions note elevated requirements in their `.DESCRIPTION` block.

---

## Installation

**End users — install from a release:**

```powershell
irm https://raw.githubusercontent.com/jschell/DirectoryServicesToolkit/main/install.ps1 | iex
```

The script downloads the latest release zip, extracts the compiled `.psm1` and `.psd1`, and
places them in your user PowerShell module path. After install:

```powershell
Import-Module DirectoryServicesToolkit
```

**Contributors — clone and import from source:**

```powershell
git clone https://github.com/jschell/DirectoryServicesToolkit.git
cd DirectoryServicesToolkit

# Development — import via the manifest (reads correct ModuleVersion)
Import-Module ./Source/DirectoryServicesToolkit.psd1 -Force

# Distribution — concatenate into a single .psm1 and generate .psd1
Invoke-Build Build
Import-Module ./Output/DirectoryServicesToolkit.psd1 -Force
```

The build step concatenates all function files into a single `Output/DirectoryServicesToolkit.psm1` and produces a `.psd1` manifest with an explicit `FunctionsToExport` list.

---

## Functions

### Security

#### Delegation & Kerberos

| Function | Description |
|---|---|
| `Find-DSDelegation` | Enumerates unconstrained, constrained, and resource-based constrained delegation configurations |
| `Find-DSKerberoastable` | Finds accounts with SPNs set on user objects (Kerberoasting candidates) |
| `Find-DSASREPRoastable` | Finds accounts with pre-authentication disabled (AS-REP roasting candidates) |
| `Find-DSInterestingACE` | Identifies non-default ACEs on high-value objects (GenericAll, WriteDacl, etc.) |
| `Find-DSBitlockerKey` | Enumerates BitLocker recovery key objects stored in AD |
| `ConvertFrom-TrustAttributeValue` | Decodes a raw `trustAttributes` integer to a human-readable flag list |
| `New-KerberosTicketRequest` | Requests a Kerberos service ticket for a given SPN; stages the encrypted ticket in memory for offline cracking |

#### AD CS / PKI

| Function | Description |
|---|---|
| `Find-DSADCSTemplate` | Enumerates certificate templates for ESC1, ESC2, and ESC3 vulnerability conditions |
| `Find-DSADCSTemplateACL` | Reviews certificate template DACLs for non-privileged write access (ESC4 — GenericAll, WriteDacl, WriteProperty, WriteOwner) |
| `Find-DSADCSEnrollmentAgents` | Identifies templates granting Certificate Request Agent (enrollment agent) rights (ESC3) |
| `Get-DSADCSAuthority` | Enumerates Enterprise CA servers with certificate expiry and web enrollment endpoint details |
| `Test-DSADCSACL` | Reviews CA object ACLs for non-admin principals with ManageCA or ManageCertificates rights (ESC7) |
| `Test-DSADCSCAFlags` | Reads `EditFlags` from each CA server's registry; flags `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6 — all client-auth templates become ESC1-equivalent) |
| `Test-DSADCSContainerACL` | Reviews ACLs on the PKI container hierarchy (root, NTAuth, AIA, CDP, Enrollment Services) for non-privileged write access (ESC5) |
| `Test-DSADCSMappingEnforcement` | Checks `StrongCertificateBindingEnforcement` on each CA and `CT_FLAG_NO_SECURITY_EXTENSION` on templates (ESC9/ESC10) |
| `Find-DSADCSWebEnrollment` | Detects HTTP (non-HTTPS) web enrollment endpoints vulnerable to NTLM relay (ESC8) |

#### TPM & Firmware

| Function | Description |
|---|---|
| `Test-IfxTPM` | Detects Infineon TPM chips with firmware vulnerable to CVE-2017-15361 (ROCA — allows RSA private key reconstruction from the public key, compromising any certificate or BitLocker key backed by the TPM) |

#### Credential Exposure & Replication

| Function | Description |
|---|---|
| `Find-DSGPPCredential` | Scans SYSVOL for GPP XML files containing cPassword values and decrypts them |
| `Find-DSDCSyncRights` | Identifies non-privileged principals with DS-Replication-Get-Changes-All on the domain NC root |
| `Get-DSLAPSCoverage` | Assesses LAPS deployment coverage across all computer objects (legacy and Windows LAPS) |
| `Test-DSLAPSPermissions` | Reviews computer object ACLs for overly-permissive LAPS password attribute read rights |

#### ACL Abuse & Persistence

| Function | Description |
|---|---|
| `Test-DSAdminSDHolderACL` | Enumerates non-privileged write ACEs on AdminSDHolder; identifies backdoors that SDProp propagates to all protected accounts every 60 minutes |
| `Find-DSGPOPermissions` | Reviews GPO DACLs for non-privileged write access (GenericAll, WriteDacl, WriteProperty, CreateChild) |
| `Find-DSApplicationOverPrivilege` | Detects Exchange and SCCM groups with legacy over-privilege on the domain object; checks domain NC root DACL for dangerous non-admin ACEs |

### Enumeration

| Function | Description |
|---|---|
| `Get-DSAdminAccounts` | Enumerates transitive members of privileged groups (Domain Admins, Enterprise Admins, etc.) |
| `Get-DSServiceAccounts` | Discovers service accounts by SPN, description keyword, and OU naming conventions |
| `Get-DSAdminSDHolder` | Returns accounts with `adminCount=1` and flags those no longer in protected groups |
| `Get-DSComputerByProperty` | Queries computer objects with filters for OS, enabled state, and inactivity threshold |
| `Get-DSGPO` | Enumerates Group Policy Objects with link status, enforcement flags, and disabled settings |
| `Get-DSDomainObjects` | General-purpose LDAP query returning typed result objects |
| `Get-DSUserByProperty` | Queries user objects with flexible property-based filtering |
| `Get-DSKeyCredLink` | Enumerates `msDS-KeyCredentialLink` attributes (Shadow Credentials attack surface) |
| `Get-DSRODCConfig` | Enumerates all RODCs with Allowed and Denied Password Replication Policy groups; flags Tier 0 in Allowed PRP as Critical |
| `Find-DSRODCCachedCredentials` | Reads `msDS-RevealedList` per RODC — identifies accounts whose credentials are currently cached; Critical for Tier 0 |
| `Get-DSSelectiveAuth` | Checks selective authentication settings on forest trusts |
| `Get-DSMachineAccountQuota` | Checks `ms-DS-MachineAccountQuota` on the domain root (RBCD/coercion prerequisite) |
| `Find-DSUserCreatedComputers` | Identifies computer accounts created by non-admin users via `ms-DS-CreatorSID` |

### Account Hygiene

| Function | Description |
|---|---|
| `Get-DSPasswordPolicy` | Reads the default domain password policy and all Fine-Grained Password Policies (PSOs) |
| `Find-DSPasswordNotRequired` | Finds accounts with the `PASSWD_NOTREQD` UAC flag set |
| `Find-DSPasswordNeverExpires` | Finds accounts with `DONT_EXPIRE_PASSWORD` set, with SPN cross-reference |
| `Find-DSStaleAccounts` | Identifies accounts inactive beyond a configurable threshold |
| `Find-DSStalePrivilegedAccounts` | Finds disabled accounts that still hold transitive membership in Tier 0 groups (Domain Admins, Enterprise Admins, Schema Admins) |
| `Find-DSWeakEncryptionAccounts` | Detects `ENCRYPTED_TEXT_PASSWORD_ALLOWED` (reversible encryption, plaintext-equivalent) and `USE_DES_KEY_ONLY` (broken DES Kerberos) UAC flags |
| `Get-DSProtectedUsersGaps` | Flags privileged accounts not in Protected Users; detects SPN/delegation incompatibilities |
| `Get-LastLoginInDomain` | Queries the non-replicated `lastLogon` attribute across all specified DCs and returns the highest (most recent) value per user |

### Trusts

| Function | Description |
|---|---|
| `Get-DSTrustRelationship` | Enumerates all domain trusts with direction, type, transitivity, and attribute bit flags |
| `Test-DSTrustSIDFiltering` | Evaluates SID filtering status per trust and assigns a risk level (Low/Medium/High) |

### DNS

| Function | Description |
|---|---|
| `Find-DSADIDNSRecord` | Detects unexpected write access on AD-Integrated DNS zone containers and wildcard `dnsNode` records |
| `Test-DSDNSSecurity` | Assesses DNS zone security settings (dynamic update policy, zone transfer targets) via WMI |
| `Find-StaleDNSDomainRecord` | Identifies stale DNS records in domain zones |

### Domain Controllers

| Function | Description |
|---|---|
| `Get-DSReplicationStatus` | Returns per-DC, per-naming-context replication status with failure detection and Win32 error translation |
| `Get-DSSysvolHealth` | Checks SYSVOL/NETLOGON share availability, SysvolReady registry flag, and DFSR replication state |
| `Get-DSResponseTime` | Measures LDAP (389) and Global Catalog (3268) response latency across DCs |
| `Get-OSLevelDomainController` | Returns OS version information for all DCs in the domain |
| `Get-DSFunctionalLevel` | Returns domain and forest functional levels; flags levels below 2016 (Medium) or pre-2012 (High) |
| `Test-DSLDAPSigning` | Reads `ldap server integrity` from each DC's registry (0=Critical, 1=Medium, 2=Low) |
| `Test-DSLDAPChannelBinding` | Reads `LdapEnforceChannelBinding` from each DC's registry (0=Critical, 1=Medium, 2=Low) |
| `Test-DSLDAPSecurity` | Combined signing + channel binding wrapper with per-DC composite risk score |
| `Get-DSNTLMPolicy` | Reads `LmCompatibilityLevel`, `NoLMHash`, and `NtlmMinSec` flags from each DC's registry |
| `Find-DSNTLMRestrictions` | Scans SYSVOL GptTmpl.inf files for NTLM-related security option settings |
| `Test-DSSMBSigning` | Reads `RequireSecuritySignature` and `EnableSecuritySignature` from each DC's registry; DCs with LDAP signing enforced but SMB signing not required remain relay-exploitable |
| `Test-DSPrintSpooler` | Queries Print Spooler service state via CIM — Critical on DCs (MS-RPRN coercion surface) |
| `Find-DSCoercionSurface` | Composites Print Spooler state with unconstrained delegation for a combined coercion risk score |
| `Get-DSAuditPolicy` | Checks Windows Advanced Audit Policy subcategory settings on each DC via registry; flags missing Success or Failure categories (NIST AU-2/AU-12, CMMC 3.3.1/3.3.2) |
| `Get-DSKerberosPolicy` | Checks krbtgt `msDS-SupportedEncryptionTypes` and per-DC registry policy; flags DES (High), RC4 (Medium), or unset/default (Medium — OS default includes RC4) |
| `Test-DSWDigestAuth` | Reads `UseLogonCredential` from `HKLM\...\WDigest` per DC; Critical when WDigest is enabled (cleartext credentials in LSASS) |
| `Test-DSCredentialProtection` | Checks `LocalAccountTokenFilterPolicy`, `DisableRestrictedAdmin`, and Credential Guard (`LsaCfgFlags`) per DC |
| `Test-DSRemoteManagementSecurity` | Checks RDP NLA enforcement, SecurityLayer (TLS), MinEncryptionLevel, and WinRM `AllowUnencrypted` per DC |
| `Test-DSCachedCredentialPolicy` | Reads `CachedLogonsCount` from `HKLM\...\Winlogon` per DC; DCs should use 0 (MSCACHE not stored) |
| `Test-DSSysvolPermissions` | Reads NTFS ACLs on SYSVOL and NETLOGON UNC paths per DC; flags non-privileged write-equivalent ACEs |

### Reporting

| Function | Description |
|---|---|
| `Invoke-DSBaselineCapture` | Snapshots key security indicators to a timestamped JSON file |
| `Compare-DSBaseline` | Diffs two baseline JSON files and returns Added/Removed/Modified per indicator |
| `New-DSAssessmentReport` | Renders pipeline or hashtable input as an HTML or CSV report |

### Utilities

| Function | Description |
|---|---|
| `ConvertTo-Guid` | Generates a deterministic GUID from a string via MD5 hash; used for DSC node enrollment identifiers where a stable per-machine GUID is required |
| `Get-TPMDetail` | Returns TPM manufacturer, vendor ID, vendor firmware version, and specification version per computer via CIM |

---

## Risk Levels

Every function that surfaces a security finding includes a `RiskLevel` string property on its output objects, enabling consistent cross-function pipeline filtering:

```powershell
# Pull Critical and High findings from any function
Find-DSKerberoastable | Where-Object { $_.RiskLevel -in 'Critical','High' }

# Aggregate across multiple functions
@(Find-DSKerberoastable; Find-DSDelegation; Find-DSInterestingACE) |
    Where-Object { $_.RiskLevel -eq 'Critical' } |
    Select-Object RiskLevel, SamAccountName, DistinguishedName
```

| Value | Meaning |
|---|---|
| `Critical` | Directly exploitable or immediate domain compromise path. Remediate within 24 hours. |
| `High` | Significantly elevated attack surface. Requires prompt remediation. |
| `Medium` | Elevated risk requiring additional attacker-controlled conditions. |
| `Low` | Compliant or healthy state; no immediate action required. |
| `Informational` | Present but not a vulnerability; provides assessment context. |
| `Unknown` | Data could not be collected (connectivity failure, access denied). |

For the complete per-function scoring logic, threshold rationale, and compliance control mapping against **NIST SP 800-53 Rev 5**, **NIST SP 800-207** (Zero Trust Architecture), and **CMMC Level 3** (NIST SP 800-172), see:

**[`Docs/RiskLevel-Reference.md`](Docs/RiskLevel-Reference.md)**

That document covers:
- Condition-to-level tables for all 57 functions that emit `RiskLevel`
- NIST 800-53 control identifiers per finding category (AC, IA, SC, CM, SI, AU, SA)
- NIST 800-207 Zero Trust pillar classification (Identity, Device, Network, Application Workload, Data)
- CMMC Level 3 practice mapping, including the 7 Level 3-specific practices from NIST 800-172
- Compliance-filtered reporting examples for CMMC L2/L3 gap reports and ZTA pillar validation

---

## Quick Start

```powershell
Import-Module ./Output/DirectoryServicesToolkit.psd1

# Find Kerberoastable accounts
Find-DSKerberoastable -Domain 'contoso.com'

# Check all delegation configurations
Find-DSDelegation -Domain 'contoso.com'

# AD CS — enumerate vulnerable certificate templates (ESC1/ESC2/ESC3)
Find-DSADCSTemplate -Domain 'contoso.com' | Where-Object { $_.IsVulnerable }

# AD CS — find non-privileged write ACEs on templates (ESC4)
Find-DSADCSTemplateACL -Domain 'contoso.com' | Where-Object { $_.IsVulnerable }

# AD CS — check CA servers for EDITF_ATTRIBUTESUBJECTALTNAME2 flag (ESC6)
Test-DSADCSCAFlags -Domain 'contoso.com' | Where-Object { $_.ESC6Vulnerable }

# AD CS — find HTTP enrollment endpoints (ESC8 NTLM relay targets)
Find-DSADCSWebEnrollment -Domain 'contoso.com' | Where-Object { $_.NTLMRelayRisk }

# GPP credentials in SYSVOL (suppress plaintext output)
Find-DSGPPCredential -Domain 'contoso.com' -Redact

# DCSync rights — flag non-privileged replication principals
Find-DSDCSyncRights -Domain 'contoso.com'

# LAPS deployment gaps
Get-DSLAPSCoverage -Domain 'contoso.com' | Where-Object { -not $_.HasLAPS }

# Machine account quota
Get-DSMachineAccountQuota -Domain 'contoso.com'

# LDAP signing + channel binding assessment
Test-DSLDAPSecurity -Domain 'contoso.com' | Where-Object { -not $_.IsFullyCompliant }

# SMB signing enforcement per DC
Test-DSSMBSigning -Domain 'contoso.com' | Where-Object { -not $_.IsCompliant }

# NTLM policy per DC
Get-DSNTLMPolicy -Domain 'contoso.com' | Where-Object { $_.LmCompatibilityLevel -lt 5 }

# Print Spooler coercion surface on DCs
Test-DSPrintSpooler -Domain 'contoso.com' | Where-Object { $_.SpoolerRunning }

# Composite coercion risk (Spooler + unconstrained delegation)
Find-DSCoercionSurface -Domain 'contoso.com' | Where-Object { $_.CompositeRisk -eq 'Critical' }

# Disabled accounts still holding Tier 0 group membership
Find-DSStalePrivilegedAccounts -Domain 'contoso.com'

# Accounts with reversible encryption or DES-only Kerberos flags
Find-DSWeakEncryptionAccounts -Domain 'contoso.com' | Where-Object { $_.RiskLevel -ne 'Medium' }

# Privileged accounts not in Protected Users
Get-DSProtectedUsersGaps -Domain 'contoso.com' | Where-Object { -not $_.InProtectedUsers }

# RODC Password Replication Policy — flag Tier 0 in Allowed PRP
Get-DSRODCConfig -Domain 'contoso.com' | Where-Object { $_.Tier0InAllowedPRP }

# RODC cached credentials — surface any Tier 0 accounts cached on an RODC
Find-DSRODCCachedCredentials -Domain 'contoso.com' -HighlightTier0

# Evaluate trust SID filtering
Test-DSTrustSIDFiltering -Domain 'contoso.com'

# Capture a security baseline
Invoke-DSBaselineCapture -Domain 'contoso.com' -OutputPath C:\Baselines

# Generate an HTML report from multiple findings
$findings = @{
    Kerberoastable = Find-DSKerberoastable -Domain 'contoso.com'
    ADCSTemplates  = Find-DSADCSTemplate   -Domain 'contoso.com' | Where-Object { $_.IsVulnerable }
    DCSync         = Find-DSDCSyncRights   -Domain 'contoso.com'
    LAPSGaps       = Get-DSLAPSCoverage    -Domain 'contoso.com' | Where-Object { -not $_.HasLAPS }
}
New-DSAssessmentReport -InputObject $findings -Domain 'contoso.com' -OutputPath C:\Reports
```

---

## Build Tasks

All tasks are defined in `build.ps1` and invoked via `Invoke-Build` (alias `ib`):

```powershell
Invoke-Build Test      # Run all Pester unit tests
Invoke-Build Lint      # Run PSScriptAnalyzer
Invoke-Build LintFix   # Run PSScriptAnalyzer with auto-fix
Invoke-Build Build     # Concatenate all .ps1 files into a single .psm1, generate .psd1
Invoke-Build CI        # Lint → Test → Build
Invoke-Build Docs      # Generate markdown docs from comment-based help
Invoke-Build Clean     # Remove build artifacts
```

Run tests directly:

```powershell
# All unit tests
Invoke-Pester ./Tests/Unit/ -Output Detailed

# By tag
Invoke-Pester ./Tests/ -Tag Security -Output Detailed

# Single function
Invoke-Pester ./Tests/Unit/Security/Find-DSDelegation.Tests.ps1 -Output Detailed
```

---

## Project Layout

```
DirectoryServicesToolkit/
├── Source/
│   ├── DirectoryServicesToolkit.psm1   # Root module — dot-sources all functions
│   ├── Security/
│   ├── Enumeration/
│   ├── AccountHygiene/
│   ├── Trusts/
│   ├── DNS/
│   ├── DomainControllers/
│   ├── Reporting/
│   ├── Utilities/
│   └── Private/                        # Internal helpers (not exported)
├── Tests/
│   ├── Unit/                           # Pester 5.x unit tests (no domain required)
│   ├── Integration/                    # Tests requiring domain connectivity
│   └── TestHelpers/
│       └── Mocks.ps1
├── Plans/                              # Implementation plans per priority
├── Docs/                               # Generated by platyPS
├── Output/                             # Build artifacts (git-ignored)
├── build.ps1
├── PSScriptAnalyzerSettings.psd1
└── CLAUDE.md
```

---

## Remote and Alternate-Credential Usage

`-Server` and `-Credential` parameters are not currently implemented. This section documents why and what a complete implementation would require, so the gap is understood before deploying in assessments from non-domain-joined workstations.

### Why they are absent

The module's private helpers use two mechanisms that do not accept credentials at the call site:

**LDAP queries (`Invoke-DSDirectorySearch`, `Get-DSObjectAcl`)**
Both use the implicit `[adsisearcher][adsi]$LdapPath` cast, which binds using the current process identity. To support alternate credentials, every helper would need to construct an explicit `[System.DirectoryServices.DirectoryEntry]::new($path, $username, $password)` and wrap it in a `[System.DirectoryServices.DirectorySearcher]`.

**Domain/DC resolution (`Resolve-DSDomainName`, `Get-DSDomainControllerNames`, `Get-DSPdcEmulatorName`, `Get-DSReplicationNeighborData`)**
All four use `[System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('Domain', $domain)` without credentials. The credential-aware overload is `DirectoryContext('Domain', $domain, $username, $password)`.

**Registry reads (`Test-DSLDAPSigning`, `Test-DSLDAPChannelBinding`, `Get-DSNTLMPolicy`, `Test-DSSMBSigning`, `Test-DSADCSCAFlags`)**
`[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey()` uses the current session's identity and has no credential parameter in the .NET API. Alternate credentials require either Windows impersonation (P/Invoke) or switching the transport to WinRM (`Invoke-Command -Credential`), which adds a WinRM dependency alongside the existing RemoteRegistry dependency.

**CIM functions (`Get-DSSysvolHealth`, `Test-DSPrintSpooler`, `Get-DSResponseTime`)**
These already use `New-CimSession`, which does accept `-Credential`. This family is the closest to ready; it would need only the CimSession construction updated.

**SYSVOL UNC paths (`Find-DSNTLMRestrictions`, `Find-DSGPPCredential`)**
Access `\\domain\SYSVOL\...` directly. Alternate credentials require mapping a PSDrive or a `net use` mount before the UNC path is accessible, then unmounting afterward.

### What a complete implementation requires

1. Update all six private helpers to accept optional `[PSCredential]$Credential` and `[string]$Server` parameters and use the credential-aware constructor overloads.
2. Add `[string]$Server` and `[PSCredential]$Credential` to the `Param` block of every public function.
3. When `$Server` is specified, prefix all LDAP paths as `LDAP://$Server/<DN>` instead of `LDAP://<DN>`.
4. Pass `$Credential` through to every private helper call.
5. For registry-reading functions: when `$Credential` is present, use `Invoke-Command -ComputerName $dc -Credential $Credential` to execute the registry read inside a remote session; fall back to `OpenRemoteBaseKey` when no credential is supplied.
6. For SYSVOL functions: mount a temporary PSDrive with the supplied credential before enumerating the UNC path, and remove it in the `End` block.

### Current workaround

Run PowerShell under the assessment account using `runas /netonly` or from a machine already joined to the target domain with the correct credentials in the current session:

```powershell
# Spawn a credential-aware shell (Kerberos ticket obtained via /netonly)
runas /netonly /user:CONTOSO\assessor powershell.exe

# Inside that shell, all module calls use the supplied identity
Import-Module DirectoryServicesToolkit
Find-DSKerberoastable -Domain 'contoso.com'
```

---

## Design Principles

- **No RSAT dependency** — uses `System.DirectoryServices` (.NET) directly
- **Structured output** — all functions return `[PSCustomObject]` for pipeline composition
- **No `Write-Host`** — progress uses `Write-Verbose`; output goes to the pipeline only
- **Unit-testable** — internal calls use mockable private helpers (`Invoke-DSDirectorySearch`, `Get-DSObjectAcl`)
- **LDAP injection safe** — user-supplied filter values are escaped before embedding in LDAP queries

--- 

## License

MIT — see [LICENSE](LICENSE).

