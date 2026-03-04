function Test-DSPrintSpooler
{
<#
.SYNOPSIS
Enumerates Print Spooler service state across domain controllers and member servers.

.DESCRIPTION
Queries the Win32_Service class via CIM on each domain controller (and optionally all
servers) to determine whether the Print Spooler service is running. A running Spooler
service on a domain controller is a critical finding because MS-RPRN (Print Spooler
protocol) can be used to coerce NTLM authentication from any machine, including DCs,
enabling relay attacks and — on DCs with unconstrained delegation — TGT capture.
Requires WMI/CIM access to target hosts.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeAllServers
When specified, also queries non-DC computer objects with server operating systems.

.EXAMPLE
Test-DSPrintSpooler -Domain 'contoso.com'

Returns Print Spooler state for all domain controllers in contoso.com.

.EXAMPLE
Test-DSPrintSpooler -Domain 'contoso.com' | Where-Object { $_.SpoolerRunning }

Returns only DCs or servers with the Spooler service actively running.

.NOTES
#### Name:    Test-DSPrintSpooler
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
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter(HelpMessage = 'Also query non-DC server computer objects')]
        [switch]$IncludeAllServers
    )

    Begin
    {
        try
        {
            $dcNames = Get-DSDomainControllerNames -Domain $Domain
        }
        catch
        {
            Write-Error "Cannot enumerate domain controllers for '$Domain': $_"
            return
        }

        $targets = New-Object System.Collections.ArrayList

        foreach ($dc in $dcNames)
        {
            [void]$targets.Add([PSCustomObject]@{ Name = $dc; Role = 'DomainController' })
        }

        if ($IncludeAllServers)
        {
            try
            {
                $DomainName = Resolve-DSDomainName -Domain $Domain
            }
            catch
            {
                Write-Verbose "Could not resolve domain name for server enumeration: $_"
                $DomainName = $Domain
            }

            $domainDN   = 'DC=' + ($DomainName -replace '\.', ',DC=')
            $ldapPath   = "LDAP://$domainDN"
            $ldapFilter = '(&(objectClass=computer)(operatingSystem=*Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
            $properties = @('name', 'dNSHostName', 'operatingSystem')

            $serverResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

            foreach ($srv in $serverResults)
            {
                $dnsName = if ($null -ne $srv['dnshostname'] -and $srv['dnshostname'].Count -gt 0) { [string]$srv['dnshostname'][0] } else { [string]$srv['name'][0] }

                # Skip if already in DC list
                if ($targets | Where-Object { $_.Name -eq $dnsName }) { continue }

                [void]$targets.Add([PSCustomObject]@{ Name = $dnsName; Role = 'MemberServer' })
            }
        }

        Write-Verbose "Checking Print Spooler on $($targets.Count) target(s)"

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        foreach ($target in $targets)
        {
            Write-Verbose "Querying Spooler on: $($target.Name)"

            $spoolerState = $null
            $spoolerRunning = $false
            $errorMessage = $null

            try
            {
                $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='Spooler'" -ComputerName $target.Name -ErrorAction Stop

                if ($null -ne $svc)
                {
                    $spoolerState   = $svc.State
                    $spoolerRunning = ($svc.State -eq 'Running')
                }
                else
                {
                    $spoolerState = 'NotInstalled'
                }
            }
            catch
            {
                $errorMessage = "CIM access failed: $_"
                Write-Verbose "Could not query Spooler on '$($target.Name)': $_"
            }

            $riskLevel = if ($spoolerRunning -and $target.Role -eq 'DomainController') { 'Critical' }
                         elseif ($spoolerRunning) { 'High' }
                         else { 'Low' }

            [void]$results.Add(
                [PSCustomObject]@{
                    Hostname       = $target.Name
                    Role           = $target.Role
                    SpoolerState   = $spoolerState
                    SpoolerRunning = $spoolerRunning
                    RiskLevel      = $riskLevel
                    Finding        = if ($spoolerRunning) { "Print Spooler is running on $($target.Role) '$($target.Name)' — coercion attack surface exposed" } else { $null }
                    ErrorMessage   = $errorMessage
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property SpoolerRunning -Descending
    }
}
