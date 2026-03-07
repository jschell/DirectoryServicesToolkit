function Find-DSNTLMRestrictions
{
<#
.SYNOPSIS
Audits SYSVOL GPO inf files for NTLM-related security option settings.

.DESCRIPTION
Scans GptTmpl.inf files in the SYSVOL Policies folder for NTLM-related registry value
settings, including LmCompatibilityLevel, NoLMHash, and NTLM restriction policies.
The absence of enforced NTLM restriction GPOs at the domain or DC OU level indicates
that NTLM hardening relies on defaults rather than policy, increasing risk surface.
Requires read access to the domain SYSVOL share (\\domain\SYSVOL).

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Find-DSNTLMRestrictions -Domain 'contoso.com'

Scans SYSVOL GPOs for NTLM-related security settings in contoso.com.

.EXAMPLE
Find-DSNTLMRestrictions -Domain 'contoso.com' | Group-Object -Property GPOGuid

Groups NTLM settings by GPO for a consolidated view.

.NOTES
#### Name:    Find-DSNTLMRestrictions
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-04::0.1.0
- Initial creation
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(HelpMessage = 'DNS name of the target domain')]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN
    )

    Begin
    {
        $sysvolPath = "\\$Domain\SYSVOL\$Domain\Policies"
        Write-Verbose "Scanning SYSVOL for NTLM restriction settings: $sysvolPath"

        # Registry value keys commonly found in GptTmpl.inf related to NTLM
        $ntlmKeys = @(
            'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
            'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'
            'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictNTLM'
            'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'
            'MACHINE\System\CurrentControlSet\Services\Rdr\Parameters\RequireSecuritySignature'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        try
        {
            $infFiles = Get-ChildItem -Path $sysvolPath -Recurse -Filter 'GptTmpl.inf' -ErrorAction Stop
        }
        catch
        {
            Write-Error "Cannot access SYSVOL at '$sysvolPath': $_"
            return
        }

        foreach ($infFile in $infFiles)
        {
            Write-Verbose "Examining: $($infFile.FullName)"

            try
            {
                $content = Get-Content -Path $infFile.FullName -ErrorAction Stop
            }
            catch
            {
                Write-Verbose "Could not read '$($infFile.FullName)': $_"
                continue
            }

            # Extract GPO GUID from path
            $gpoGuid = $null
            if ($infFile.FullName -match '\{([0-9A-Fa-f-]{36})\}')
            {
                $gpoGuid = $Matches[1]
            }

            $foundSettings = @{}

            foreach ($line in $content)
            {
                foreach ($key in $ntlmKeys)
                {
                    if ($line -match [regex]::Escape($key))
                    {
                        $shortKey = $key.Split('\')[-1]
                        $value    = if ($line -match '=\s*(.+)$') { $Matches[1].Trim() } else { 'Present' }
                        $foundSettings[$shortKey] = $value
                    }
                }
            }

            foreach ($settingName in $foundSettings.Keys)
            {
                [void]$results.Add(
                    [PSCustomObject]@{
                        GPOGuid       = $gpoGuid
                        FilePath      = $infFile.FullName
                        SettingName   = $settingName
                        SettingValue  = $foundSettings[$settingName]
                        HasNTLMPolicy = $true
                        # RiskLevel: each row confirms an NTLM restriction policy is enforced
                        # via GPO. Presence is a positive control. The *absence* of any results
                        # from this function indicates missing NTLM hardening (see Verbose output).
                        RiskLevel     = 'Informational'
                    }
                )
            }
        }
    }

    End
    {
        if ($results.Count -eq 0)
        {
            Write-Verbose 'No NTLM restriction settings found in any GPO — domain may lack enforced NTLM hardening policy'
        }

        $results.ToArray()
    }
}
