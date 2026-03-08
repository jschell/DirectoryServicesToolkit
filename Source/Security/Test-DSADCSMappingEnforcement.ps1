function Test-DSADCSMappingEnforcement
{
<#
.SYNOPSIS
Checks whether certificate-to-account strong mapping enforcement is configured on each CA.

.DESCRIPTION
Evaluates ESC9 and ESC10 exposure by inspecting two complementary controls:

1. StrongCertificateBindingEnforcement registry value on each CA host:
     HKLM\SYSTEM\CurrentControlSet\Services\Kdc
   Controls whether the KDC enforces strong certificate-to-account mapping (KB5014754):
     0 = Compatibility mode — accepts weak mappings (vulnerable)
     1 = Compatibility mode with audit events — still accepts weak mappings (partial)
     2 = Full enforcement — rejects weak mappings (secure)

2. CT_FLAG_NO_SECURITY_EXTENSION (0x00080000) flag in each certificate template's
   msPKI-Certificate-Name-Flag LDAP attribute. When set on a template, issued
   certificates will not contain the SID extension, defeating strong mapping
   enforcement and creating ESC9 exposure.

Risk classification:
  StrongCertificateBindingEnforcement = 2 AND no templates flagged  → Low
  StrongCertificateBindingEnforcement = 1 OR templates flagged       → Medium
  StrongCertificateBindingEnforcement = 0 OR registry inaccessible   → High

Requires RemoteRegistry on CA hosts and LDAP read access to the Configuration NC.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Test-DSADCSMappingEnforcement -Domain 'contoso.com'

Returns certificate mapping enforcement posture for each CA and any flagged templates.

.EXAMPLE
Test-DSADCSMappingEnforcement | Where-Object { $_.RiskLevel -ne 'Low' }

Returns CAs or templates reducing strong mapping enforcement.

.NOTES
#### Name:    Test-DSADCSMappingEnforcement
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-08::0.1.0
- Initial creation — ESC9/ESC10 certificate mapping enforcement check

NIST 800-53: SC-17, IA-5(2), IA-9
NIST 800-207: Identity pillar — certificate-based authentication assurance
CMMC Level 3: 3.5.3 (use multi-factor authentication), 3.13.8

.LINK
https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
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
        try
        {
            $DomainName = Resolve-DSDomainName -Domain $Domain
        }
        catch
        {
            Write-Error "Cannot connect to domain '$Domain': $_"
            return
        }

        Write-Verbose "Checking ADCS mapping enforcement for domain: $DomainName"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $configNC = "CN=Configuration,$domainDN"

        $kdcRegistryPath   = 'SYSTEM\CurrentControlSet\Services\Kdc'
        $noSecurityExtFlag = 0x00080000

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        # ── Part 1: Check StrongCertificateBindingEnforcement per CA host ──
        $caLdapPath   = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        $caLdapFilter = '(objectClass=pKIEnrollmentService)'
        $caProperties = @('name', 'dNSHostName', 'distinguishedName')

        $caEntries = Invoke-DSDirectorySearch -LdapPath $caLdapPath -Filter $caLdapFilter -Properties $caProperties

        foreach ($ca in $caEntries)
        {
            $caName    = [string]$ca['name'][0]
            $caHost    = if ($ca['dnshostname']) { [string]$ca['dnshostname'][0] } else { $caName }
            $errorMessage = $null
            $rawValue     = $null

            Write-Verbose "Checking StrongCertificateBindingEnforcement on CA host: $caHost"

            try
            {
                $regBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine,
                    $caHost
                )
                $subKey = $regBase.OpenSubKey($kdcRegistryPath)

                if ($null -ne $subKey)
                {
                    $rawValue = $subKey.GetValue('StrongCertificateBindingEnforcement')
                    $subKey.Close()
                }

                $regBase.Close()
            }
            catch
            {
                $errorMessage = "Registry access failed on '$caHost': $_"
                Write-Verbose $errorMessage
            }

            $enforcementValue = if ($null -ne $rawValue) { [int]$rawValue } else { $null }

            $riskLevel = if ($null -ne $errorMessage -and $null -eq $enforcementValue)
            {
                'High'
            }
            elseif ($null -eq $enforcementValue -or $enforcementValue -eq 0)
            {
                'High'
            }
            elseif ($enforcementValue -eq 1)
            {
                'Medium'
            }
            else
            {
                'Low'
            }

            $description = switch ($enforcementValue)
            {
                $null { 'StrongCertificateBindingEnforcement not set — weak mapping accepted (ESC10 vulnerable)' }
                0     { 'Compatibility mode, no audit — weak certificate mapping accepted (ESC10 vulnerable)' }
                1     { 'Compatibility mode with audit events — weak mapping still accepted, ESC10 partially mitigated' }
                2     { 'Full enforcement — weak certificate mappings rejected' }
                default { "Unknown enforcement value: $enforcementValue" }
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    ObjectType                        = 'CA'
                    CAName                            = $caName
                    CAHost                            = $caHost
                    StrongCertificateBindingEnforcement = $enforcementValue
                    Description                       = $description
                    RiskLevel                         = $riskLevel
                    IsCompliant                       = ($enforcementValue -eq 2)
                    Finding                           = if ($riskLevel -ne 'Low') { "ESC10: CA '$caName' has StrongCertificateBindingEnforcement=$enforcementValue — $description" } else { $null }
                    ErrorMessage                      = $errorMessage
                }
            )
        }

        # ── Part 2: Check templates for CT_FLAG_NO_SECURITY_EXTENSION ──
        $tmplLdapPath   = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        $tmplLdapFilter = '(objectClass=pKICertificateTemplate)'
        $tmplProperties = @('name', 'distinguishedName', 'msPKI-Certificate-Name-Flag')

        $templates = Invoke-DSDirectorySearch -LdapPath $tmplLdapPath -Filter $tmplLdapFilter -Properties $tmplProperties

        foreach ($tmpl in $templates)
        {
            $templateName = [string]$tmpl['name'][0]
            $templateDN   = [string]$tmpl['distinguishedname'][0]
            $nameFlagRaw  = if ($tmpl['mspki-certificate-name-flag']) { $tmpl['mspki-certificate-name-flag'][0] } else { 0 }
            $nameFlagInt  = [int]$nameFlagRaw

            $noSecExt = [bool]($nameFlagInt -band $noSecurityExtFlag)

            if (-not $noSecExt) { continue }

            [void]$results.Add(
                [PSCustomObject]@{
                    ObjectType                        = 'Template'
                    CAName                            = $null
                    CAHost                            = $null
                    TemplateName                      = $templateName
                    TemplateDN                        = $templateDN
                    NameFlag                          = $nameFlagInt
                    NoSecurityExtensionSet            = $noSecExt
                    Description                       = "Template '$templateName' has CT_FLAG_NO_SECURITY_EXTENSION set — issued certs omit SID extension, defeating strong mapping"
                    RiskLevel                         = 'High'
                    IsCompliant                       = $false
                    Finding                           = "ESC9: Template '$templateName' has CT_FLAG_NO_SECURITY_EXTENSION (0x{0:X8}) set" -f $noSecurityExtFlag
                    ErrorMessage                      = $null
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property RiskLevel, ObjectType
    }
}
