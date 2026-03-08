function Get-DSFunctionalLevel
{
<#
.SYNOPSIS
Retrieves the domain and forest functional level from Active Directory.

.DESCRIPTION
Reads the msDS-Behavior-Version attribute from the domain NC root and the
Partitions container to determine domain and forest functional levels.

Functional levels determine which advanced AD features are available and which
DC operating systems can participate in the domain. Older functional levels indicate
the presence of legacy DCs or configuration debt that may carry security risk.

Domain Functional Level values (msDS-Behavior-Version on domain NC root):
  0  = Windows 2000 Native
  1  = Windows Server 2003 Interim
  2  = Windows Server 2003
  3  = Windows Server 2008
  4  = Windows Server 2008 R2
  5  = Windows Server 2012
  6  = Windows Server 2012 R2
  7  = Windows Server 2016
  10 = Windows Server 2019 / 2022

Risk classification:
  DFL >= 7 (2016+) AND FFL >= 7    → Low
  DFL >= 5 (2012+) AND FFL >= 5    → Medium
  DFL < 5 (pre-2012) OR FFL < 5   → High

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Get-DSFunctionalLevel -Domain 'contoso.com'

Returns the domain and forest functional levels for contoso.com.

.EXAMPLE
Get-DSFunctionalLevel | Where-Object { $_.RiskLevel -ne 'Low' }

Returns domains with outdated functional levels.

.NOTES
#### Name:    Get-DSFunctionalLevel
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-08::0.1.0
- Initial creation — domain and forest functional level check

NIST 800-53: CM-2, CM-6, SA-22
NIST 800-207: (supports all pillars via modern feature availability)
CMMC Level 3: 3.4.1 (establish/maintain baseline configurations)

.LINK
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels
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

        Write-Verbose "Querying functional levels for domain: $DomainName"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')

        $levelNames = @{
            0  = 'Windows 2000 Native'
            1  = 'Windows Server 2003 Interim'
            2  = 'Windows Server 2003'
            3  = 'Windows Server 2008'
            4  = 'Windows Server 2008 R2'
            5  = 'Windows Server 2012'
            6  = 'Windows Server 2012 R2'
            7  = 'Windows Server 2016'
            10 = 'Windows Server 2019 / 2022'
        }
    }

    Process
    {
        # ── Domain Functional Level ──
        $dflFilter = '(objectClass=domain)'
        $dflProps  = @('distinguishedName', 'msDS-Behavior-Version')
        $dflEntry  = Invoke-DSDirectorySearch -Filter $dflFilter -Properties $dflProps -Domain $DomainName -SearchScope 'Base'

        $dflInt = $null
        if ($dflEntry -and $dflEntry[0]['msds-behavior-version'])
        {
            $dflInt = [int]$dflEntry[0]['msds-behavior-version'][0]
        }

        # ── Forest Functional Level ──
        # Read the forest-wide DFL from the Configuration NC Partitions container
        $partitionLdapPath = "LDAP://CN=Partitions,CN=Configuration,$domainDN"
        $partitionFilter   = '(objectClass=crossRefContainer)'
        $partitionProps    = @('msDS-Behavior-Version')

        $fflEntry = Invoke-DSDirectorySearch -LdapPath $partitionLdapPath -Filter $partitionFilter -Properties $partitionProps -SearchScope 'Base'

        $fflInt = $null
        if ($fflEntry -and $fflEntry[0]['msds-behavior-version'])
        {
            $fflInt = [int]$fflEntry[0]['msds-behavior-version'][0]
        }

        $dflName = if ($null -ne $dflInt -and $levelNames.ContainsKey($dflInt)) { $levelNames[$dflInt] } else { "Unknown ($dflInt)" }
        $fflName = if ($null -ne $fflInt -and $levelNames.ContainsKey($fflInt)) { $levelNames[$fflInt] } else { "Unknown ($fflInt)" }

        $riskLevel = if ($null -eq $dflInt -or $null -eq $fflInt)
        {
            'Unknown'
        }
        elseif ($dflInt -lt 5 -or $fflInt -lt 5)
        {
            'High'
        }
        elseif ($dflInt -lt 7 -or $fflInt -lt 7)
        {
            'Medium'
        }
        else
        {
            'Low'
        }

        $issues = @()
        if ($null -ne $dflInt -and $dflInt -lt 7) { $issues += "Domain functional level $dflInt ($dflName) is below Windows Server 2016" }
        if ($null -ne $fflInt -and $fflInt -lt 7) { $issues += "Forest functional level $fflInt ($fflName) is below Windows Server 2016" }

        [PSCustomObject]@{
            Domain                  = $DomainName
            DomainFunctionalLevel   = $dflInt
            DomainFunctionalName    = $dflName
            ForestFunctionalLevel   = $fflInt
            ForestFunctionalName    = $fflName
            Issues                  = $issues
            RiskLevel               = $riskLevel
            IsCompliant             = ($riskLevel -eq 'Low')
        }
    }

    End { }
}
