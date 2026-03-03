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

| Function | Description |
|---|---|
| `Find-DSDelegation` | Enumerates unconstrained, constrained, and resource-based constrained delegation configurations |
| `Find-DSKerberoastable` | Finds accounts with SPNs set on user objects (Kerberoasting candidates) |
| `Find-DSASREPRoastable` | Finds accounts with pre-authentication disabled (AS-REP roasting candidates) |
| `Find-DSInterestingACE` | Identifies non-default ACEs on high-value objects (GenericAll, WriteDacl, etc.) |
| `Find-DSBitlockerKey` | Enumerates BitLocker recovery key objects stored in AD |
| `ConvertFrom-TrustAttributeValue` | Decodes a raw `trustAttributes` integer to a human-readable flag list |

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
| `Get-DSSelectiveAuth` | Checks selective authentication settings on forest trusts |

### Account Hygiene

| Function | Description |
|---|---|
| `Get-DSPasswordPolicy` | Reads the default domain password policy and all Fine-Grained Password Policies (PSOs) |
| `Find-DSPasswordNotRequired` | Finds accounts with the `PASSWD_NOTREQD` UAC flag set |
| `Find-DSPasswordNeverExpires` | Finds accounts with `DONT_EXPIRE_PASSWORD` set, with SPN cross-reference |
| `Find-DSStaleAccounts` | Identifies accounts inactive beyond a configurable threshold |

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

# Evaluate trust SID filtering
Test-DSTrustSIDFiltering -Domain 'contoso.com'

# Check DNS zone security
Test-DSDNSSecurity -Domain 'contoso.com'

# Capture a security baseline
Invoke-DSBaselineCapture -Domain 'contoso.com' -OutputPath C:\Baselines

# Compare two baselines
Compare-DSBaseline -BaselinePath C:\Baselines\contoso-old.json `
                   -CurrentPath  C:\Baselines\contoso-new.json

# Generate an HTML report from multiple findings
$findings = @{
    Kerberoastable = Find-DSKerberoastable -Domain 'contoso.com'
    Delegation     = Find-DSDelegation     -Domain 'contoso.com'
    StaleAccounts  = Find-DSStaleAccounts  -Domain 'contoso.com'
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
