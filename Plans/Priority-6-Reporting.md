# Implementation Plan — Priority 6: Reporting & Baseline

**Functions:** `Invoke-DSBaselineCapture`, `Compare-DSBaseline`, `New-DSAssessmentReport`

---

## Invoke-DSBaselineCapture

### Approach

Call each selected indicator function, capture output, serialize the combined
snapshot to a timestamped JSON file. Each indicator is run in a `try/catch` so
a single function failure does not abort the entire capture.

### Indicator → Function Mapping

| Indicator name | Function | Output type |
|---|---|---|
| `AdminAccounts` | `Get-DSAdminAccounts` | `PSCustomObject[]` |
| `Delegation` | `Find-DSDelegation` | `PSCustomObject[]` |
| `Trusts` | `Get-DSTrustRelationship` | `PSCustomObject[]` |
| `PasswordPolicy` | `Get-DSPasswordPolicy` | `PSCustomObject[]` |
| `Kerberoastable` | `Find-DSKerberoastable` | `PSCustomObject[]` |
| `ASREPRoastable` | `Find-DSASREPRoastable` | `PSCustomObject[]` |
| `AdminSDHolder` | `Get-DSAdminSDHolder` | `PSCustomObject[]` |

### JSON File Naming

```powershell
$timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH-mm-ssZ')
$fileName  = "{0}-baseline-{1}.json" -f $Domain, $timestamp
$fullPath  = Join-Path $OutputPath $fileName
```

### JSON Document Schema

```json
{
  "Schema": "1.0",
  "CapturedAt": "2026-03-03T10:00:00Z",
  "Domain": "contoso.com",
  "Indicators": {
    "AdminAccounts": [ ... ],
    "Delegation": [ ... ],
    "Trusts": [ ... ],
    "PasswordPolicy": [ ... ],
    "Kerberoastable": [ ... ],
    "ASREPRoastable": [ ... ],
    "AdminSDHolder": [ ... ]
  },
  "CaptureErrors": {
    "IndicatorName": "Error message if capture failed"
  }
}
```

### Serialization

```powershell
$snapshot = [ordered]@{
    Schema       = '1.0'
    CapturedAt   = (Get-Date).ToUniversalTime().ToString('o')
    Domain       = $Domain
    Indicators   = [ordered]@{}
    CaptureErrors = [ordered]@{}
}

foreach ($indicator in $Indicators)
{
    try
    {
        $result = & "{ function map call }" -Domain $Domain
        $snapshot.Indicators[$indicator] = $result
    }
    catch
    {
        $snapshot.CaptureErrors[$indicator] = $_.Exception.Message
        Write-Warning "Failed to capture $indicator : $_"
    }
}

$snapshot | ConvertTo-Json -Depth 10 | Set-Content -Path $fullPath -Encoding UTF8
```

Use `-Depth 10` to ensure nested objects are fully serialized.

### Return Value

Return the full path to the written file as a `[string]`:
```powershell
Write-Verbose "Baseline written to: $fullPath"
$fullPath
```

### Implementation Steps

1. `Begin {}` — validate `$OutputPath` exists; create if not; build file name
2. `Process {}` — iterate indicators; call each function; populate snapshot hashtable
3. `End {}` — serialize to JSON; write file; return path

---

## Compare-DSBaseline

### Approach

Load both JSON files. For each indicator present in both, compute a structured
diff using identity keys appropriate to the indicator type.

### Identity Keys Per Indicator

| Indicator | Identity Key |
|---|---|
| `AdminAccounts` | `DistinguishedName` |
| `Delegation` | `DistinguishedName + DelegationType` |
| `Trusts` | `Name` (trusted domain DNS name) |
| `PasswordPolicy` | `Name + PolicyType` |
| `Kerberoastable` | `DistinguishedName` |
| `ASREPRoastable` | `DistinguishedName` |
| `AdminSDHolder` | `DistinguishedName` |

### Diff Algorithm

For each indicator:

```powershell
# Convert arrays to hashtables keyed by identity key
$baselineMap = @{}
foreach ($item in $baseline.Indicators.$indicator)
{
    $baselineMap[$item.$identityKey] = $item
}

$currentMap = @{}
foreach ($item in $current.Indicators.$indicator)
{
    $currentMap[$item.$identityKey] = $item
}

$added   = $currentMap.Keys  | Where-Object { -not $baselineMap.ContainsKey($_) } | ForEach-Object { $currentMap[$_] }
$removed = $baselineMap.Keys | Where-Object { -not $currentMap.ContainsKey($_) }  | ForEach-Object { $baselineMap[$_] }
# Modified: present in both but at least one property differs
$modified = $currentMap.Keys | Where-Object { $baselineMap.ContainsKey($_) } | ForEach-Object {
    $b = $baselineMap[$_] | ConvertTo-Json -Depth 5
    $c = $currentMap[$_]  | ConvertTo-Json -Depth 5
    if ($b -ne $c) { [PSCustomObject]@{ Baseline = $baselineMap[$_]; Current = $currentMap[$_] } }
}
```

### Output Schema

```powershell
[PSCustomObject]@{
    BaselineCapturedAt  = [string]
    CurrentCapturedAt   = [string]
    Domain              = [string]
    Diffs = [ordered]@{
        AdminAccounts = [PSCustomObject]@{
            Added    = [object[]]
            Removed  = [object[]]
            Modified = [PSCustomObject[]]  # each has .Baseline and .Current
        }
        # ... one entry per indicator
    }
    Summary = [PSCustomObject]@{
        TotalAdded    = [int]
        TotalRemoved  = [int]
        TotalModified = [int]
        HasChanges    = [bool]
    }
}
```

### Indicator Filtering

When `-Indicator` is specified, only process those indicator names.
Emit `Write-Warning` if a requested indicator is missing from either file.

### Implementation Steps

1. `Begin {}` — load both files via `Get-Content | ConvertFrom-Json`; validate `Schema` version
2. `Process {}` — iterate indicators; compute diff per indicator; populate `Diffs` hashtable
3. Compute `Summary` totals
4. `End {}` — emit result object

---

## New-DSAssessmentReport

### Approach

Accept piped or parameter `$InputObject`. Determine format (`HTML` or `CSV`) and
render accordingly. Return the output file path as a string.

### Input Normalization

The function must handle two input forms:
1. **Hashtable** — `@{ SectionName = @(...objects...) }`
2. **Raw pipeline** — a flat array of `PSCustomObject` from a single function call

Detect via `$InputObject -is [hashtable]`.

For raw pipeline input, accumulate objects in `Begin/Process/End` and treat as
a single `Ungrouped` section.

### CSV Format

Simple: `$allObjects | Export-Csv -Path $filePath -NoTypeInformation`

For hashtable input, add a `Category` column before export:
```powershell
foreach ($section in $InputObject.GetEnumerator())
{
    $section.Value | Select-Object @{N='Category'; E={$section.Key}}, * | Export-Csv -Path $filePath -Append -NoTypeInformation
}
```

### HTML Format

Generate a self-contained HTML file with:
- A header section: title, domain, capture timestamp, toolkit version
- An executive summary table: section name, item count, risk indicator
- One section per input key containing a styled `<table>` of results

HTML structure:
```
<html>
  <head>
    <style> ... (embedded minimal CSS) </style>
  </head>
  <body>
    <h1>$Title</h1>
    <p>Domain: $Domain | Generated: $timestamp</p>
    <h2>Executive Summary</h2>
    <table> ... </table>
    <h2>AdminAccounts</h2>
    <table> ... </table>
    <h2>Delegation</h2>
    <table> ... </table>
    ...
  </body>
</html>
```

**Minimal CSS** (inline, no external dependencies):
```css
body { font-family: Consolas, monospace; font-size: 13px; margin: 20px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
th { background: #2c3e50; color: white; padding: 6px 10px; text-align: left; }
td { padding: 4px 10px; border-bottom: 1px solid #ddd; }
tr:hover { background: #f5f5f5; }
.risk-high   { color: #c0392b; font-weight: bold; }
.risk-medium { color: #e67e22; }
.risk-low    { color: #27ae60; }
h2 { color: #2c3e50; border-bottom: 2px solid #2c3e50; padding-bottom: 4px; margin-top: 30px; }
```

### HTML Table Generation

Convert objects to HTML table rows:
```powershell
function ConvertTo-HtmlTable
{
    param([object[]]$Objects, [string]$Caption)

    if (-not $Objects -or $Objects.Count -eq 0)
    {
        return "<p><em>No items found.</em></p>"
    }

    $headers = $Objects[0].PSObject.Properties.Name
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("<table>")
    [void]$sb.AppendLine("  <thead><tr>")
    foreach ($h in $headers) { [void]$sb.AppendLine("    <th>$h</th>") }
    [void]$sb.AppendLine("  </tr></thead><tbody>")
    foreach ($obj in $Objects)
    {
        [void]$sb.AppendLine("  <tr>")
        foreach ($h in $headers) { [void]$sb.AppendLine("    <td>$([System.Web.HttpUtility]::HtmlEncode($obj.$h))</td>") }
        [void]$sb.AppendLine("  </tr>")
    }
    [void]$sb.AppendLine("  </tbody></table>")
    $sb.ToString()
}
```

Note: `[System.Web.HttpUtility]::HtmlEncode()` prevents XSS in output values.
This class is available in .NET 5+ without additional imports.

### Output File Naming

```powershell
$ext      = if ($Format -eq 'HTML') { 'html' } else { 'csv' }
$timestamp = (Get-Date).ToString('yyyy-MM-dd')
$fileName = "{0}-{1}.{2}" -f ($Title -replace '\s+','-'), $timestamp, $ext
$fullPath = Join-Path $OutputPath $fileName
```

### Implementation Steps

1. `Begin {}` — initialize accumulator for pipeline input; validate `$OutputPath`
2. `Process {}` — accumulate piped objects
3. `End {}` — normalize input to section hashtable; render HTML or CSV; write file; return path

### Tests

```
Tests/Unit/Reporting/New-DSAssessmentReport.Tests.ps1
```

Test: HTML output contains expected section headers; CSV output contains `Category` column;
empty sections display "No items found" message; output file is written to `$OutputPath`.
