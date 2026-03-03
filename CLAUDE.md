# CLAUDE.md — PowerShell Module Development Guide

This file provides guidance to Claude Code when working in this PowerShell repository. It covers development commands, code style conventions, testing patterns, and project structure.

## Development Environment

### Requirements

* PowerShell 7.4+ (pwsh) — all scripts target PS 7.x unless noted. Run `pwsh --version` to verify.
* Pester 5.x — test framework. Install via `Install-PSResource Pester -Scope CurrentUser`
* PSScriptAnalyzer — linting. Install via `Install-PSResource PSScriptAnalyzer -Scope CurrentUser`
* platyPS — documentation generation. Install via `Install-PSResource platyPS -Scope CurrentUser`
* Invoke-Build — task runner (equivalent to make/npm scripts). Install via `Install-PSResource InvokeBuild -Scope CurrentUser`

### Verify environment

```powershell
# Check all required tools are present
pwsh --version                                  # Should be 7.4+
pwsh -c "Get-Module Pester -ListAvailable"      # Should be 5.x
pwsh -c "Get-Module PSScriptAnalyzer -ListAvailable"
pwsh -c "Get-Module InvokeBuild -ListAvailable"
```

## Build Commands

All primary tasks are defined in `build.ps1` and invoked via Invoke-Build (aliased as `ib`).

### Common tasks

```powershell
# Run all tests
Invoke-Build Test

# Run linter only
Invoke-Build Lint

# Run linter and fix auto-fixable issues
Invoke-Build LintFix

# Build the module (compile manifest, copy files to output)
Invoke-Build Build

# Run full CI pipeline: lint → test → build
Invoke-Build CI

# Generate documentation from comment-based help
Invoke-Build Docs

# Clean build artifacts
Invoke-Build Clean
```

### Running tests directly

```powershell
# Run all tests
Invoke-Pester ./Tests/ -Output Detailed

# Run a single test file
Invoke-Pester ./Tests/Unit/Get-DSDomainObjects.Tests.ps1 -Output Detailed

# Run only tests tagged 'Unit'
Invoke-Pester ./Tests/ -Tag Unit -Output Detailed

# Run with code coverage
Invoke-Pester ./Tests/ -CodeCoverage ./Source/**/*.ps1 -CodeCoverageOutputFile coverage.xml
```

### Linting directly

```powershell
# Lint entire source tree
Invoke-ScriptAnalyzer -Path ./Source/ -Recurse -Settings ./PSScriptAnalyzerSettings.psd1

# Lint a single file
Invoke-ScriptAnalyzer -Path ./Source/Enumeration/Get-DSDomainObjects.ps1

# Auto-fix safe rules
Invoke-ScriptAnalyzer -Path ./Source/ -Recurse -Fix
```

### Module import during development

```powershell
# Import the module from source (not installed copy)
Import-Module ./Output/ModuleName.psd1 -Force

# Verify functions exported correctly
Get-Command -Module ModuleName

# Remove and reimport cleanly
Remove-Module ModuleName -ErrorAction SilentlyContinue
Import-Module ./Output/ModuleName.psd1 -Force
```

## Code Style

### Naming conventions

Follow PowerShell's approved verb-noun format. Use `Get-Verb` to verify approved verbs.

```powershell
# Correct — approved verb, PascalCase noun
function Get-DSDomainObjects { }
function Find-DSKerberoastable { }
function ConvertFrom-TrustAttributeValue { }

# Wrong — unapproved verb, inconsistent casing
function Fetch-DSObjects { }     # 'Fetch' is not an approved verb
function get-dsobjects { }       # lowercase
function GetDSObjects { }        # missing hyphen
```

Noun infix conventions:
* `DS` — Directory Services / Active Directory functions (e.g., `Get-DSDomainObjects`)
* No infix — general utilities not specific to a domain (e.g., `ConvertTo-Guid`, `Get-FirmwareType`)

### Function structure

Every function must follow this template:

```powershell
function Verb-NounName {
    <#
    .SYNOPSIS
    One-line description of what the function does.

    .DESCRIPTION
    Full description. Include any dependencies, permissions required,
    or environmental prerequisites.

    .PARAMETER ParameterName
    Description of this parameter.

    .PARAMETER AnotherParam
    Description of this parameter.

    .EXAMPLE
    Verb-NounName -ParameterName 'value'

    Description of what this example demonstrates.

    .EXAMPLE
    'value1','value2' | Verb-NounName

    Pipeline input example.

    .NOTES
    #### Name: Verb-NounName
    #### Author: J Schell
    #### Version: 0.1.0
    #### License: MIT License

    Changelog:
    2025-08-15::0.1.0
    - Initial creation

    .LINK
    https://gist.github.com/jschell/GISTID
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory, ValueFromPipeline, HelpMessage = 'Description of this parameter')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ParameterName,

        [Parameter()]
        [ValidateSet('Option1','Option2')]
        [string]$AnotherParam = 'Option1',

        [Parameter()]
        [switch]$SomeSwitch
    )

    Begin
    {
        # One-time setup, validate environment, open connections
    }

    Process
    {
        foreach ($item in $ParameterName)
        {
            # Per-item processing
        }
    }

    End
    {
        # Cleanup, close connections, return aggregated results
    }
}
```

### CmdletBinding and parameters

* Always use `[CmdletBinding()]` — provides `-Verbose`, `-Debug`, `-WhatIf`, `-Confirm` automatically
* Always declare `[OutputType()]` when the output type is known
* Use `[Parameter(Mandatory)]` rather than `[Parameter(Mandatory=$true)]` (cleaner PS 5+ syntax)
* Use `[ValidateNotNullOrEmpty()]` on string parameters that cannot be empty
* Use `[ValidateSet()]` for parameters with a fixed set of valid values
* Pipeline-aware functions must use `Begin`/`Process`/`End` blocks — even if `Begin` and `End` are empty

### Brace and indentation style

This codebase uses **Allman style** (braces on their own line), not K&R:

```powershell
# Correct — Allman style
function Get-Example
{
    if ($condition)
    {
        Do-Something
    }
    else
    {
        Do-Other
    }
}

# Wrong — K&R style (not used here)
function Get-Example {
    if ($condition) {
        Do-Something
    }
}
```

* 4 spaces for indentation — no tabs
* One blank line between logical sections within a function
* One blank line between functions

### Error handling

Prefer terminating errors for unrecoverable conditions; use `-ErrorAction` for recoverable ones:

```powershell
# Terminating error — function cannot continue
if (-not (Test-Path $Path))
{
    throw "Path '$Path' does not exist"
}

# Non-terminating with fallback
$result = Get-ADUser $Name -ErrorAction SilentlyContinue
if (-not $result)
{
    Write-Warning "User '$Name' not found, skipping"
    return
}

# Structured error handling for external calls
try
{
    $response = Invoke-RestMethod -Uri $Uri -Headers $headers
}
catch [System.Net.WebException]
{
    Write-Error "Network error contacting '$Uri': $_"
    return
}
catch
{
    throw
}
```

### Output

* Use `Write-Verbose` for progress/debug messages — never `Write-Host` in library functions
* Return objects, not formatted strings — let the caller decide how to display
* Use `[PSCustomObject]` with explicit property names for structured output
* Do not use `return` at the end of a function just to output a variable — PS outputs automatically

```powershell
# Correct — output a typed object
[PSCustomObject]@{
    ComputerName = $computer
    OSVersion    = $os
    IsVulnerable = $vuln
}

# Wrong — formatted string output
Write-Host "$computer is running $os"
"$computer,$os,$vuln"   # Don't output CSV strings from library functions
```

### DirectoryServices vs ActiveDirectory module

Prefer `System.DirectoryServices` (native .NET) over the `ActiveDirectory` RSAT module unless there is a specific capability gap:

```powershell
# Preferred — no RSAT dependency
$searcher = [System.DirectoryServices.DirectorySearcher]::new()
$searcher.Filter = '(&(objectClass=user)(sAMAccountName=jsmith))'
$searcher.SearchRoot = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$Domain")

# Acceptable when DirectoryServices won't work
Import-Module ActiveDirectory -ErrorAction Stop
Get-ADUser -Filter { SamAccountName -eq 'jsmith' }
```

### String formatting

Use string formatting consistently:

```powershell
# Correct
$message = "Processing {0} of {1}: {2}" -f $i, $total, $item

# Also acceptable for simple cases
$message = "User: $($user.SamAccountName)"

# Avoid
$message = "User: " + $user.SamAccountName + " found"
```

## Testing

Tests live in `./Tests/` mirroring the source structure:

```
Tests/
├── Unit/
│   ├── Enumeration/
│   │   └── Get-DSDomainObjects.Tests.ps1
│   ├── Security/
│   │   └── Find-DSBitlockerKey.Tests.ps1
│   └── ...
├── Integration/
│   └── ...        # Tests requiring domain connectivity — skipped in CI
└── TestHelpers/
    └── Mocks.ps1  # Shared mock/stub helpers
```

### Pester test structure

```powershell
BeforeAll {
    # Import the module being tested
    Import-Module "$PSScriptRoot/../../../Output/ModuleName.psd1" -Force

    # Load shared helpers if needed
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSDomainObjects' {

    Context 'When valid domain is provided' {

        BeforeEach {
            # Mock external calls — never hit a real domain in unit tests
            Mock Invoke-DirectorySearch { return $script:MockDomainObjects }
        }

        It 'Should return a PSCustomObject for each result' {
            $result = Get-DSDomainObjects -Domain 'contoso.com'
            $result | Should -BeOfType [PSCustomObject]
        }

        It 'Should include expected properties' {
            $result = Get-DSDomainObjects -Domain 'contoso.com'
            $result.Name        | Should -Not -BeNullOrEmpty
            $result.DistinguishedName | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When domain is unreachable' {

        BeforeEach {
            Mock Invoke-DirectorySearch { throw 'Domain not found' }
        }

        It 'Should write an error and return nothing' {
            { Get-DSDomainObjects -Domain 'notreal.local' } | Should -Not -Throw
            # Verify Write-Error was called
        }
    }
}
```

### Test tagging

Tag tests to allow selective runs:

```powershell
Describe 'Get-DSDomainObjects' -Tag 'Unit', 'Enumeration' {
    It 'Should return results' -Tag 'Smoke' {
        ...
    }
}
```

Standard tags: `Unit`, `Integration`, `Smoke`, `Security`, `Enumeration`, `DomainControllers`, `DNS`

### Mocking DirectoryServices

Unit tests must never connect to a real directory. Use Pester mocks or stub classes:

```powershell
# In TestHelpers/Mocks.ps1
$script:MockDomainObjects = @(
    [PSCustomObject]@{ Name = 'TestUser1'; DistinguishedName = 'CN=TestUser1,DC=contoso,DC=com' }
    [PSCustomObject]@{ Name = 'TestUser2'; DistinguishedName = 'CN=TestUser2,DC=contoso,DC=com' }
)

# In test file
Mock Get-DSObjectFromDirectory { return $script:MockDomainObjects } -ModuleName ModuleName
```

## Project Structure

```
./
├── CLAUDE.md                       # This file
├── README.md
├── build.ps1                       # Invoke-Build task file
├── PSScriptAnalyzerSettings.psd1   # Linter configuration
├── ModuleName.psd1                 # Module manifest (generated by build)
│
├── Source/
│   ├── ModuleName.psm1             # Root module file (dot-sources all functions)
│   ├── Enumeration/
│   │   ├── Get-DSDomainObjects.ps1
│   │   ├── Get-DSUserByProperty.ps1
│   │   └── ...
│   ├── Security/
│   │   ├── Find-DSBitlockerKey.ps1
│   │   ├── Find-DSDelegation.ps1
│   │   └── ...
│   ├── AccountHygiene/
│   ├── Trusts/
│   ├── DomainControllers/
│   ├── DNS/
│   ├── Reporting/
│   └── Utilities/
│
├── Tests/
│   ├── Unit/
│   ├── Integration/
│   └── TestHelpers/
│
├── Docs/                           # Generated by platyPS from comment-based help
│   └── en-US/
│       └── Get-DSDomainObjects.md
│
└── Output/                         # Build artifacts — git ignored
    ├── ModuleName.psd1
    └── ModuleName.psm1
```

### One function per file

Each public function lives in its own `.ps1` file named exactly after the function:

```
Source/Enumeration/Get-DSDomainObjects.ps1      ✅
Source/Enumeration/DomainObjects.ps1            ❌
Source/Enumeration/EnumerationFunctions.ps1     ❌
```

Private/helper functions used only within the module live in `Source/Private/` and are not exported.

## Module Manifest

The manifest (`ModuleName.psd1`) is generated by the build. Do not edit it manually. Key fields:

```powershell
@{
    ModuleVersion     = '0.1.0'
    GUID              = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    Author            = 'J Schell'
    Description       = 'Active Directory security assessment toolkit'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Get-DSDomainObjects'
        'Get-DSUserByProperty'
        # ... all public functions listed explicitly
        # Never use '*' — always enumerate
    )
    PrivateData = @{
        PSData = @{
            Tags    = @('ActiveDirectory','Security','Audit')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
```

## Documentation

Documentation is generated from comment-based help using platyPS:

```powershell
# Generate markdown docs from loaded module
Import-Module ./Output/ModuleName.psd1
New-MarkdownHelp -Module ModuleName -OutputFolder ./Docs/en-US -Force

# Update existing docs after modifying help
Update-MarkdownHelp -Path ./Docs/en-US
```

Comment-based help requirements:
* `.SYNOPSIS` — mandatory, one line
* `.DESCRIPTION` — mandatory, explain behavior, dependencies, required permissions
* `.PARAMETER` — required for every parameter
* `.EXAMPLE` — minimum one example; two examples for complex functions
* `.NOTES` — mandatory, include Name/Author/Version/License block and changelog
* `.LINK` — include Gist URL for functions sourced from Gist

## Versioning

Semantic versioning applies at the function level via the `.NOTES` changelog:

```
0.1.0 — Initial creation
0.1.1 — Bug fix / minor change (no interface change)
0.2.0 — New parameter added (backwards compatible)
1.0.0 — Breaking parameter or output change
```

Module-level version in the manifest is bumped by the build process based on the highest function version.

## Git Conventions

### Commit message format

```
<type>(<scope>): <short description>

<body — explain what changed and why, not how>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

Scopes match module folders: `enumeration`, `security`, `dns`, `dcs`, `hygiene`, `trusts`, `reporting`, `utils`

Examples:

```
feat(security): add Find-DSDelegation for unconstrained/constrained/RBCD detection

Adds three-mode delegation enumeration covering unconstrained (TrustedForDelegation),
constrained (msDS-AllowedToDelegateTo), and resource-based constrained delegation
(msDS-AllowedToActOnBehalfOfOtherIdentity). Includes -ExcludeComputerAccounts switch.
```

```
fix(enumeration): handle size limit exceeded in Get-DSKeyCredLink

Large domains could hit the default DirectorySearcher PageSize limit, causing silent
truncation. Sets PageSize to 1000 and uses paged search to retrieve all results.
```

```
docs(security): update Find-DSBitlockerKey comment-based help
```

### Branch naming

```
feat/find-dsdelegation
fix/get-dskeycrednlink-sizelimit
docs/find-dsbitlocker-help
test/get-dsdomainobjects-pester5
refactor/enumeration-private-helpers
```

### Before committing

```powershell
# Must pass before any commit
Invoke-Build Lint   # Zero errors, zero warnings
Invoke-Build Test   # 100% pass, no skipped tests in Unit suite
```

## PSScriptAnalyzer Rules

The settings file (`PSScriptAnalyzerSettings.psd1`) enforces:

```powershell
@{
    Rules = @{
        PSUseApprovedVerbs            = @{ Enable = $true }
        PSAvoidUsingWriteHost         = @{ Enable = $true }
        PSUseShouldProcessForStateChangingFunctions = @{ Enable = $true }
        PSAvoidUsingInvokeExpression  = @{ Enable = $true }
        PSUsePSCredentialType         = @{ Enable = $true }
        PSAvoidUsingPlainTextForPassword = @{ Enable = $true }
        PSAvoidUsingConvertToSecureStringWithPlainText = @{ Enable = $true }
        PSUseOutputTypeCorrectly      = @{ Enable = $true }
        PSUseCmdletCorrectly          = @{ Enable = $true }
    }
    ExcludeRules = @(
        # Allow positional parameters in short utility/pipeline scenarios
        'PSAvoidUsingPositionalParameters'
    )
}
```

Hard rules — these are never suppressed:
* No `Write-Host` in module functions
* No plain-text passwords or credentials
* No `Invoke-Expression` with external input
* No `ConvertTo-SecureString -AsPlainText`

Suppression syntax (use sparingly, requires comment justification):

```powershell
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingInvokeExpression',
    '',
    Justification = 'Input is fully validated against an allowlist before evaluation'
)]
```

## Security Considerations

Functions in this toolkit operate in privileged AD contexts. Keep these in mind:

* **No credential storage** — never write credentials to disk, logs, or pipeline output. Use `[PSCredential]` and pass through only; never log `.GetNetworkCredential().Password`
* **Least privilege comments** — document in `.DESCRIPTION` what AD permissions the function requires (e.g., "Requires Domain Admin or delegated read access to the `msFVEObject` class")
* **Sensitive output** — functions returning BitLocker keys, Kerberos tickets, or credential material should write to the pipeline only, never to verbose/debug streams
* **Input validation** — validate all string inputs that become LDAP filter values to prevent LDAP injection
* **LDAP filter escaping** — escape special characters in user-supplied values before embedding in LDAP filters:

```powershell
function Escape-LdapFilter
{
    param([string]$Value)
    $Value -replace '\\', '\5c' `
           -replace '\*', '\2a' `
           -replace '\(', '\28' `
           -replace '\)', '\29' `
           -replace '\x00', '\00'
}
```

## Common Patterns

### Paged DirectorySearcher

Use this pattern for any query that may return large result sets:

```powershell
$searcher = [System.DirectoryServices.DirectorySearcher]::new()
$searcher.Filter   = $ldapFilter
$searcher.PageSize = 1000
$searcher.SearchScope = 'Subtree'

if ($PSBoundParameters.ContainsKey('SizeLimit'))
{
    $searcher.SizeLimit = $SizeLimit
}

$searcher.PropertiesToLoad.AddRange($propertiesToReturn)

$results = $searcher.FindAll()
try
{
    foreach ($result in $results)
    {
        # process $result.Properties
    }
}
finally
{
    $results.Dispose()
}
```

### Multi-DC queries (non-replicated attributes)

For `lastlogon` and other non-replicated attributes, query all DCs:

```powershell
$domainControllers = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers

foreach ($dc in $domainControllers)
{
    $entry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$($dc.Name)")
    # query $entry
}
```

### ShouldProcess for state-changing functions

Any function that modifies AD objects must implement ShouldProcess:

```powershell
function Set-DSExample
{
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(...)

    Process
    {
        if ($PSCmdlet.ShouldProcess($target, 'Modify attribute'))
        {
            # Make the change
        }
    }
}
```

## Migration Notes

When making breaking changes to existing functions (parameter renames, output schema changes, removed functionality), document them in `MIGRATION.md`:

```markdown
## v0.2.0 → v1.0.0

### Get-DSDomainObjects
- Parameter `-ObjectType` renamed to `-Class` for consistency with LDAP terminology
- Output property `DN` renamed to `DistinguishedName`
```

---

*Last updated: 2026-03-02 — covers PS 7.4+, Pester 5.x, PSScriptAnalyzer 1.21+*
