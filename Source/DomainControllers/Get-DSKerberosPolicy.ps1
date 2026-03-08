function Get-DSKerberosPolicy
{
<#
.SYNOPSIS
Checks the domain Kerberos encryption policy and supported encryption types per DC.

.DESCRIPTION
Evaluates two complementary Kerberos encryption controls:

1. Domain Default Domain Policy Kerberos settings (read from the domain object's
   msDS-SupportedEncryptionTypes attribute and the krbtgt account attribute):
   - msDS-SupportedEncryptionTypes on the domain object (bitmask)
   - msDS-SupportedEncryptionTypes on the krbtgt account

2. Per-DC registry setting controlling supported Kerberos encryption types:
     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters
     SupportedEncryptionTypes (bitmask)

Encryption type bitmask values:
  0x01  DES-CBC-CRC       — weak, should not be present
  0x02  DES-CBC-MD5       — weak, should not be present
  0x04  RC4-HMAC-MD5      — legacy, considered weak (CMMC/NIST recommend disabling)
  0x08  AES128-CTS-HMAC-SHA1-96 — acceptable
  0x10  AES256-CTS-HMAC-SHA1-96 — recommended
  0x20  AES256-CTS-HMAC-SHA1-96 (future)

Risk classification:
  AES-only, no RC4/DES                          → Low
  RC4 present but no DES                        → Medium
  DES present OR encryption types not restricted → High

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Get-DSKerberosPolicy -Domain 'contoso.com'

Returns Kerberos encryption policy for the domain and each DC.

.EXAMPLE
Get-DSKerberosPolicy | Where-Object { $_.DESEnabled }

Returns DCs or domain objects with DES encryption still enabled.

.NOTES
#### Name:    Get-DSKerberosPolicy
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-08::0.1.0
- Initial creation — Kerberos encryption type policy check

NIST 800-53: SC-13, IA-5(1), SC-8
NIST 800-207: Identity pillar — cryptographic assurance of authentication
CMMC Level 3: 3.13.8 (implement cryptographic mechanisms), 3.5.10

.LINK
https://learn.microsoft.com/en-us/windows-server/security/kerberos/preventing-kerberos-change-password-that-uses-rc4-secret-keys
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

        try
        {
            $dcNames = Get-DSDomainControllerNames -Domain $Domain
        }
        catch
        {
            Write-Error "Cannot enumerate domain controllers for '$Domain': $_"
            return
        }

        Write-Verbose "Checking Kerberos encryption policy for domain: $DomainName"

        $domainDN    = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $kerbRegPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'

        # Encryption type bitmask constants
        $DES_CBC_CRC  = 0x01
        $DES_CBC_MD5  = 0x02
        $RC4_HMAC     = 0x04
        $AES128       = 0x08
        $AES256       = 0x10

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        # ── Domain-level: krbtgt account encryption types ──
        $krbtgtFilter = '(&(objectClass=user)(sAMAccountName=krbtgt))'
        $krbtgtProps  = @('sAMAccountName', 'msDS-SupportedEncryptionTypes', 'distinguishedName')
        $krbtgtEntry  = Invoke-DSDirectorySearch -Filter $krbtgtFilter -Properties $krbtgtProps -Domain $DomainName

        if ($krbtgtEntry)
        {
            $encTypeRaw = if ($krbtgtEntry[0]['msds-supportedencryptiontypes']) { $krbtgtEntry[0]['msds-supportedencryptiontypes'][0] } else { 0 }
            $encTypeInt = [int]$encTypeRaw

            $desEnabled  = [bool](($encTypeInt -band $DES_CBC_CRC) -or ($encTypeInt -band $DES_CBC_MD5))
            $rc4Enabled  = [bool]($encTypeInt -band $RC4_HMAC)
            $aes128      = [bool]($encTypeInt -band $AES128)
            $aes256      = [bool]($encTypeInt -band $AES256)

            $riskLevel = if ($desEnabled) { 'High' }
                         elseif ($rc4Enabled) { 'Medium' }
                         elseif ($encTypeInt -eq 0) { 'Medium' }
                         else { 'Low' }

            [void]$results.Add(
                [PSCustomObject]@{
                    ObjectType              = 'Domain (krbtgt)'
                    Name                    = 'krbtgt'
                    SupportedEncryptionTypes = $encTypeInt
                    DESEnabled              = $desEnabled
                    RC4Enabled              = $rc4Enabled
                    AES128Enabled           = $aes128
                    AES256Enabled           = $aes256
                    RiskLevel               = $riskLevel
                    IsCompliant             = ($riskLevel -eq 'Low')
                    ErrorMessage            = $null
                }
            )
        }

        # ── Per-DC: registry encryption type policy ──
        foreach ($dc in $dcNames)
        {
            Write-Verbose "Querying Kerberos encryption policy on: $dc"

            $rawValue     = $null
            $errorMessage = $null

            try
            {
                $regBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine,
                    $dc
                )
                $subKey = $regBase.OpenSubKey($kerbRegPath)

                if ($null -ne $subKey)
                {
                    $rawValue = $subKey.GetValue('SupportedEncryptionTypes')
                    $subKey.Close()
                }

                $regBase.Close()
            }
            catch
            {
                $errorMessage = "Registry access failed: $_"
                Write-Verbose "Could not query registry on '$dc': $_"
            }

            $encTypeInt  = if ($null -ne $rawValue) { [int]$rawValue } else { $null }

            $desEnabled  = if ($null -ne $encTypeInt) { [bool](($encTypeInt -band $DES_CBC_CRC) -or ($encTypeInt -band $DES_CBC_MD5)) } else { $false }
            $rc4Enabled  = if ($null -ne $encTypeInt) { [bool]($encTypeInt -band $RC4_HMAC) } else { $true }  # Absent = OS default includes RC4
            $aes128      = if ($null -ne $encTypeInt) { [bool]($encTypeInt -band $AES128) } else { $true }
            $aes256      = if ($null -ne $encTypeInt) { [bool]($encTypeInt -band $AES256) } else { $true }

            $riskLevel = if ($null -ne $errorMessage -and $null -eq $encTypeInt)
            {
                'Unknown'
            }
            elseif ($null -eq $encTypeInt)
            {
                'Medium'   # Key absent — OS defaults, which include RC4
            }
            elseif ($desEnabled)
            {
                'High'
            }
            elseif ($rc4Enabled)
            {
                'Medium'
            }
            else
            {
                'Low'
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    ObjectType               = 'DC'
                    Name                     = $dc
                    SupportedEncryptionTypes = $encTypeInt
                    DESEnabled               = $desEnabled
                    RC4Enabled               = $rc4Enabled
                    AES128Enabled            = $aes128
                    AES256Enabled            = $aes256
                    RiskLevel                = $riskLevel
                    IsCompliant              = ($riskLevel -eq 'Low')
                    ErrorMessage             = $errorMessage
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property ObjectType, IsCompliant, Name
    }
}
