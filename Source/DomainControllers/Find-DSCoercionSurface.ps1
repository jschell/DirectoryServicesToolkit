function Find-DSCoercionSurface
{
<#
.SYNOPSIS
Identifies machines combining Print Spooler exposure with unconstrained delegation.

.DESCRIPTION
Composites two high-risk conditions: (1) Print Spooler service running (MS-RPRN coercion
surface) and (2) unconstrained delegation configured on the machine account. A machine
meeting both criteria is a critical finding because an attacker who triggers Spooler-based
coercion from that host can capture TGTs for the coerced account via the unconstrained
delegation ticket cache. Domain controllers are inherently trusted for unconstrained
delegation, so any DC with Spooler running is Critical. Requires WMI/CIM access to
targets and read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Find-DSCoercionSurface -Domain 'contoso.com'

Returns composite coercion risk assessment for all DCs and unconstrained-delegation hosts.

.EXAMPLE
Find-DSCoercionSurface -Domain 'contoso.com' | Where-Object { $_.CompositeRisk -eq 'Critical' }

Returns only critical composite findings.

.NOTES
#### Name:    Find-DSCoercionSurface
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
        try
        {
            $DomainName = Resolve-DSDomainName -Domain $Domain
        }
        catch
        {
            Write-Error "Cannot connect to domain '$Domain': $_"
            return
        }

        Write-Verbose "Assessing coercion surface in domain: $DomainName"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $ldapPath = "LDAP://$domainDN"

        # Find computer objects with unconstrained delegation (TrustedForDelegation)
        # UAC bit 0x80000 = TRUSTED_FOR_DELEGATION
        $ldapFilter = '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
        $properties = @('name', 'dNSHostName', 'userAccountControl', 'distinguishedName')

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $unconstrainedHosts = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($entry in $unconstrainedHosts)
        {
            $hostname = if ($null -ne $entry['dnshostname'] -and $entry['dnshostname'].Count -gt 0) { [string]$entry['dnshostname'][0] } else { [string]$entry['name'][0] }
            $uac      = if ($null -ne $entry['useraccountcontrol'] -and $entry['useraccountcontrol'].Count -gt 0) { [int]$entry['useraccountcontrol'][0] } else { 0 }

            # DC bit: SERVER_TRUST_ACCOUNT = 0x2000
            $isDC = [bool]($uac -band 0x2000)

            Write-Verbose "Checking Spooler on unconstrained-delegation host: $hostname"

            $spoolerRunning = $false
            $spoolerState   = 'Unknown'
            $errorMessage   = $null

            try
            {
                $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='Spooler'" -ComputerName $hostname -ErrorAction Stop

                if ($null -ne $svc)
                {
                    $spoolerState   = $svc.State
                    $spoolerRunning = ($svc.State -eq 'Running')
                }
            }
            catch
            {
                $errorMessage = "CIM access failed: $_"
                Write-Verbose "Could not query Spooler on '$hostname': $_"
            }

            $compositeRisk = if ($spoolerRunning -and $isDC) { 'Critical' }
                             elseif ($spoolerRunning) { 'High' }
                             elseif ($isDC) { 'High' }
                             else { 'Medium' }

            [void]$results.Add(
                [PSCustomObject]@{
                    Hostname             = $hostname
                    DistinguishedName    = [string]$entry['distinguishedname'][0]
                    IsDomainController   = $isDC
                    UnconstrainedDelegate = $true
                    SpoolerState         = $spoolerState
                    SpoolerRunning       = $spoolerRunning
                    CompositeRisk        = $compositeRisk
                    Finding              = "Host '$hostname' has unconstrained delegation$(if ($spoolerRunning) { ' AND running Print Spooler' }) — coercion attack risk"
                    ErrorMessage         = $errorMessage
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property CompositeRisk, Hostname
    }
}
