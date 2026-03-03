function New-DSAssessmentReport
{
<#
.SYNOPSIS
Aggregates output from multiple toolkit functions into a structured report.

.DESCRIPTION
Accepts pipeline or parameter input from Get-DS* and Find-DS* functions and
generates a structured HTML or CSV report suitable for delivering assessment
findings. Designed for use at the end of an assessment pipeline.

Report sections mirror the toolkit categories:
  - Executive Summary (counts, risk ratings)
  - Enumeration findings
  - Security findings (delegation, Kerberoast, AS-REP, ACE abuse)
  - Account hygiene findings
  - Trust findings
  - Domain Controller health
  - DNS findings

When piping from multiple functions, use a [hashtable] to group results
by category. See examples.

.PARAMETER InputObject
Results from one or more toolkit functions. Accepts pipeline input.

.PARAMETER OutputPath
The directory where the report file is written. Defaults to the current
working directory.

.PARAMETER Format
Output format: HTML or CSV. Defaults to HTML.

.PARAMETER Title
The report title string. Defaults to "AD Security Assessment Report".

.PARAMETER Domain
Domain name to include in the report header.

.EXAMPLE
Find-DSKerberoastable | New-DSAssessmentReport -Domain 'contoso.com'

Generates an HTML report from Kerberoastable account findings.

.EXAMPLE
$findings = @{
    Kerberoastable = Find-DSKerberoastable -Domain 'contoso.com'
    Delegation     = Find-DSDelegation -Domain 'contoso.com'
    StaleAccounts  = Find-DSStaleAccounts -Domain 'contoso.com'
}
New-DSAssessmentReport -InputObject $findings -Domain 'contoso.com' -OutputPath C:\Reports

Generates a multi-section report from several findings collections.

.NOTES
#### Name:    New-DSAssessmentReport
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-03::0.1.0
- Initial creation
#>

    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    Param
    (
        [Parameter(ValueFromPipeline)]
        $InputObject,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = $PWD,

        [Parameter()]
        [ValidateSet('HTML', 'CSV')]
        [string]$Format = 'HTML',

        [Parameter()]
        [string]$Title = 'AD Security Assessment Report',

        [Parameter()]
        [string]$Domain
    )

    Begin
    {
        # Validate and create output directory
        if (-not (Test-Path -LiteralPath $OutputPath))
        {
            try
            {
                [void](New-Item -ItemType Directory -Path $OutputPath -Force)
            }
            catch
            {
                Write-Error "Cannot create output directory '$OutputPath': $_"
                return
            }
        }

        $pipelineObjects = [System.Collections.Generic.List[object]]::new()
    }

    Process
    {
        if ($null -ne $InputObject)
        {
            [void]$pipelineObjects.Add($InputObject)
        }
    }

    End
    {
        # ── Normalise input to a section hashtable ─────────────────────────────

        $sections = [ordered]@{}

        if ($pipelineObjects.Count -gt 0)
        {
            $firstItem = $pipelineObjects[0]

            if ($firstItem -is [hashtable] -or $firstItem -is [System.Collections.Specialized.OrderedDictionary])
            {
                # Single hashtable passed via -InputObject or pipeline
                foreach ($kvp in $firstItem.GetEnumerator())
                {
                    $sections[$kvp.Key] = @($kvp.Value)
                }
            }
            else
            {
                # Flat object collection — treat as single 'Ungrouped' section
                $sections['Ungrouped'] = $pipelineObjects.ToArray()
            }
        }

        if ($sections.Count -eq 0)
        {
            Write-Warning 'No input data provided to New-DSAssessmentReport.'
        }

        # ── Build output file path ─────────────────────────────────────────────

        $ext       = if ($Format -eq 'HTML') { 'html' } else { 'csv' }
        $fileDate  = (Get-Date).ToString('yyyy-MM-dd')
        $safeTitle = $Title -replace '\s+', '-' -replace '[^\w\-]', ''
        $fileName  = '{0}-{1}.{2}' -f $safeTitle, $fileDate, $ext
        $fullPath  = Join-Path $OutputPath $fileName

        Write-Verbose "Writing $Format report to: $fullPath"

        if (-not $PSCmdlet.ShouldProcess($fullPath, "Write $Format assessment report"))
        {
            return
        }

        # ── Render output ──────────────────────────────────────────────────────

        if ($Format -eq 'CSV')
        {
            $csvFile = $fullPath

            if ($sections.Count -eq 1 -and $sections.Keys -contains 'Ungrouped')
            {
                $sections['Ungrouped'] | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            }
            else
            {
                $firstSection = $true
                foreach ($section in $sections.GetEnumerator())
                {
                    $section.Value |
                        Select-Object @{N='Category'; E={ $section.Key }}, * |
                        Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8 -Append:(-not $firstSection)
                    $firstSection = $false
                }
            }
        }
        else
        {
            # HTML output

            $generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss UTC')
            $domainLabel = if ($Domain) { $Domain } else { '(not specified)' }

            $css = @'
body { font-family: Consolas, monospace; font-size: 13px; margin: 20px; background: #fff; }
table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
th { background: #2c3e50; color: white; padding: 6px 10px; text-align: left; }
td { padding: 4px 10px; border-bottom: 1px solid #ddd; }
tr:hover { background: #f5f5f5; }
.risk-high   { color: #c0392b; font-weight: bold; }
.risk-medium { color: #e67e22; }
.risk-low    { color: #27ae60; }
h1 { color: #2c3e50; }
h2 { color: #2c3e50; border-bottom: 2px solid #2c3e50; padding-bottom: 4px; margin-top: 30px; }
p.meta { color: #666; font-size: 12px; }
'@

            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.AppendLine('<!DOCTYPE html>')
            [void]$sb.AppendLine('<html><head><meta charset="utf-8">')
            [void]$sb.AppendLine("<title>$([System.Security.SecurityElement]::Escape($Title))</title>")
            [void]$sb.AppendLine("<style>$css</style>")
            [void]$sb.AppendLine('</head><body>')
            [void]$sb.AppendLine("<h1>$([System.Security.SecurityElement]::Escape($Title))</h1>")
            [void]$sb.AppendLine("<p class='meta'>Domain: $([System.Security.SecurityElement]::Escape($domainLabel)) &nbsp;|&nbsp; Generated: $generatedAt</p>")

            # Executive summary table
            [void]$sb.AppendLine('<h2>Executive Summary</h2>')
            [void]$sb.AppendLine('<table><thead><tr><th>Section</th><th>Item Count</th></tr></thead><tbody>')
            foreach ($section in $sections.GetEnumerator())
            {
                $count = if ($section.Value) { @($section.Value).Count } else { 0 }
                [void]$sb.AppendLine("<tr><td>$([System.Security.SecurityElement]::Escape($section.Key))</td><td>$count</td></tr>")
            }
            [void]$sb.AppendLine('</tbody></table>')

            # Per-section tables
            foreach ($section in $sections.GetEnumerator())
            {
                [void]$sb.AppendLine("<h2>$([System.Security.SecurityElement]::Escape($section.Key))</h2>")
                [void]$sb.AppendLine((ConvertTo-DSHtmlTable -Objects @($section.Value)))
            }

            [void]$sb.AppendLine('</body></html>')

            $sb.ToString() | Set-Content -Path $fullPath -Encoding UTF8
        }

        $fullPath
    }
}


function ConvertTo-DSHtmlTable
{
<#
.SYNOPSIS
Internal helper — converts an array of objects to an HTML table string.
#>
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Objects
    )

    $items = @($Objects | Where-Object { $null -ne $_ })

    if ($items.Count -eq 0)
    {
        return '<p><em>No items found.</em></p>'
    }

    $headers = $items[0].PSObject.Properties.Name
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<table>')
    [void]$sb.AppendLine('  <thead><tr>')
    foreach ($h in $headers)
    {
        [void]$sb.AppendLine("    <th>$([System.Security.SecurityElement]::Escape($h))</th>")
    }
    [void]$sb.AppendLine('  </tr></thead>')
    [void]$sb.AppendLine('  <tbody>')

    foreach ($obj in $items)
    {
        [void]$sb.AppendLine('  <tr>')
        foreach ($h in $headers)
        {
            $val = $obj.$h
            $encoded = if ($null -eq $val) { '' } else { [System.Security.SecurityElement]::Escape($val.ToString()) }
            [void]$sb.AppendLine("    <td>$encoded</td>")
        }
        [void]$sb.AppendLine('  </tr>')
    }

    [void]$sb.AppendLine('  </tbody>')
    [void]$sb.AppendLine('</table>')
    $sb.ToString()
}
