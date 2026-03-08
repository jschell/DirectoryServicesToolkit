function Test-DSADCSCAFlags
{
<#
.SYNOPSIS
Tests each Enterprise CA server for the ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 flag.

.DESCRIPTION
Reads the EditFlags value from each Enterprise CA server's registry under:
  HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA Name>\
  PolicyModules\CertificateAuthority_MicrosoftDefault.Policy

When the EDITF_ATTRIBUTESUBJECTALTNAME2 flag (0x00040000) is set, any template that
permits client authentication becomes exploitable like ESC1 regardless of template
configuration — the CA will accept a Subject Alternative Name supplied by the enrollee
in the certificate request. This is ESC6 as described in Certified Pre-Owned
(SpecterOps).

CA server hostnames are discovered from the Enrollment Services container in the
Configuration naming context. Registry access requires RemoteRegistry to be running
on each CA server and an account with remote registry read rights.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Test-DSADCSCAFlags -Domain 'contoso.com'

Returns the ESC6 flag status for every Enterprise CA in the contoso.com domain.

.EXAMPLE
Test-DSADCSCAFlags | Where-Object { $_.ESC6Vulnerable }

Returns only CA servers where EDITF_ATTRIBUTESUBJECTALTNAME2 is set.

.NOTES
#### Name:    Test-DSADCSCAFlags
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-07::0.1.0
- Initial creation — ESC6 CA EditFlags check

.LINK
https://posts.specterops.io/certified-pre-owned-d95910965cd2
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

        Write-Verbose "Querying domain: $DomainName for Enterprise CA servers (ESC6 check)"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $configNC = "CN=Configuration,$domainDN"

        $ldapPath   = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        $ldapFilter = '(objectClass=pKIEnrollmentService)'
        $properties = @(
            'name'
            'distinguishedName'
            'dNSHostName'
        )

        # EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
        $esc6FlagMask = 0x00040000

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $caObjects = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($ca in $caObjects)
        {
            $caName  = [string]$ca['name'][0]
            $dnsHost = if ($null -ne $ca['dnshostname'][0]) { [string]$ca['dnshostname'][0] } else { $caName }

            Write-Verbose "Checking EditFlags on CA '$caName' at host '$dnsHost'"

            $editFlags    = $null
            $errorMessage = $null

            $registryPath = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"
            $valueName    = 'EditFlags'

            try
            {
                $regBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine,
                    $dnsHost
                )
                $subKey = $regBase.OpenSubKey($registryPath)

                if ($null -ne $subKey)
                {
                    $editFlags = $subKey.GetValue($valueName)
                    $subKey.Close()
                }
                else
                {
                    $errorMessage = "Registry path not found — CA may not be running CertSvc or CA name mismatch"
                    Write-Verbose "Registry subkey not found on '$dnsHost': $registryPath"
                }

                $regBase.Close()
            }
            catch
            {
                $errorMessage = "Registry access failed: $_"
                Write-Verbose "Could not query registry on '$dnsHost': $_"
            }

            $editFlagsInt   = if ($null -ne $editFlags) { [int]$editFlags } else { $null }
            $esc6Vulnerable = if ($null -ne $editFlagsInt) { [bool]($editFlagsInt -band $esc6FlagMask) } else { $false }

            $riskLevel = if ($esc6Vulnerable)
            {
                'Critical'
            }
            elseif ($null -eq $editFlagsInt)
            {
                'Unknown'
            }
            else
            {
                'Low'
            }

            $finding = if ($esc6Vulnerable)
            {
                "ESC6: CA '$caName' has EDITF_ATTRIBUTESUBJECTALTNAME2 set — all client-auth templates are ESC1-equivalent"
            }
            else
            {
                $null
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    CAName          = $caName
                    DNSHostName     = $dnsHost
                    DistinguishedName = [string]$ca['distinguishedname'][0]
                    EditFlags       = $editFlagsInt
                    ESC6Vulnerable  = $esc6Vulnerable
                    RiskLevel       = $riskLevel
                    Finding         = $finding
                    ErrorMessage    = $errorMessage
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property ESC6Vulnerable -Descending
    }
}
