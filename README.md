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

# Development — import directly from source (no build step needed)
Import-Module ./Source/DirectoryServicesToolkit.psm1 -Force

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

#### AD CS / PKI

| Function | Description |
|---|---|
| `Find-DSADCSTemplate` | Enumerates certificate templates for ESC1, ESC2, and ESC3 vulnerability conditions |
| `Find-DSADCSTemplateACL` | Reviews certificate template DACLs for non-privileged write access (ESC4 — GenericAll, WriteDacl, WriteProperty, WriteOwner) |
| `Find-DSADCSEnrollmentAgents` | Identifies templates granting Certificate Request Agent (enrollment agent) rights (ESC3) |
| `Get-DSADCSAuthority` | Enumerates Enterprise CA servers with certificate expiry and web enrollment endpoint details |
| `Test-DSADCSACL` | Reviews CA object ACLs for non-admin principals with ManageCA or ManageCertificates rights (ESC7) |
| `Test-DSADCSCAFlags` | Reads `EditFlags` from each CA server's registry; flags `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6 — all client-auth templates become ESC1-equivalent) |
| `Find-DSADCSWebEnrollment` | Detects HTTP (non-HTTPS) web enrollment endpoints vulnerable to NTLM relay (ESC8) |

#### Credential Exposure & Replication

| Function | Description |
|---|---|
| `Find-DSGPPCredential` | Scans SYSVOL for GPP XML files containing cPassword values and decrypts them |
| `Find-DSDCSyncRights` | Identifies non-privileged principals with DS-Replication-Get-Changes-All on the domain NC root |
| `Get-DSLAPSCoverage` | Assesses LAPS deployment coverage across all computer objects (legacy and Windows LAPS) |
| `Test-DSLAPSPermissions` | Reviews computer object ACLs for overly-permissive LAPS password attribute read rights |

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
| `Test-DSLDAPSigning` | Reads `ldap server integrity` from each DC's registry (0=Critical, 1=Medium, 2=Compliant) |
| `Test-DSLDAPChannelBinding` | Reads `LdapEnforceChannelBinding` from each DC's registry (0=Critical, 1=Medium, 2=Compliant) |
| `Test-DSLDAPSecurity` | Combined signing + channel binding wrapper with per-DC composite risk score |
| `Get-DSNTLMPolicy` | Reads `LmCompatibilityLevel`, `NoLMHash`, and `NtlmMinSec` flags from each DC's registry |
| `Find-DSNTLMRestrictions` | Scans SYSVOL GptTmpl.inf files for NTLM-related security option settings |
| `Test-DSSMBSigning` | Reads `RequireSecuritySignature` and `EnableSecuritySignature` from each DC's registry; DCs with LDAP signing enforced but SMB signing not required remain relay-exploitable |
| `Test-DSPrintSpooler` | Queries Print Spooler service state via CIM — Critical on DCs (MS-RPRN coercion surface) |
| `Find-DSCoercionSurface` | Composites Print Spooler state with unconstrained delegation for a combined coercion risk score |

### Reporting

| Function | Description |
|---|---|
| `Invoke-DSBaselineCapture` | Snapshots key security indicators to a timestamped JSON file |
| `Compare-DSBaseline` | Diffs two baseline JSON files and returns Added/Removed/Modified per indicator |
| `New-DSAssessmentReport` | Renders pipeline or hashtable input as an HTML or CSV report |

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

## Design Principles

- **No RSAT dependency** — uses `System.DirectoryServices` (.NET) directly
- **Structured output** — all functions return `[PSCustomObject]` for pipeline composition
- **No `Write-Host`** — progress uses `Write-Verbose`; output goes to the pipeline only
- **Unit-testable** — internal calls use mockable private helpers (`Invoke-DSDirectorySearch`, `Get-DSObjectAcl`)
- **LDAP injection safe** — user-supplied filter values are escaped before embedding in LDAP queries

--- 

## License

MIT — see [LICENSE](LICENSE).

