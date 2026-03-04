function Get-DSLAPSCoverage
{
    <#
    .SYNOPSIS
    Assesses LAPS deployment coverage across all computer objects in the domain.

    .DESCRIPTION
    Queries all computer objects and checks for the presence of legacy LAPS (ms-Mcs-AdmPwd)
    or Windows LAPS (msLAPS-Password) attributes to determine deployment coverage. Computers
    lacking either attribute have unmanaged local administrator passwords. Also reports on
    expired LAPS passwords (ms-Mcs-AdmPwdExpirationTime in the past) and aggregates coverage
    statistics per OU. Requires read access to the domain partition. Reading the password
    attribute itself requires delegated LAPS read rights.

    .PARAMETER Domain
    The DNS name of the domain to query. Defaults to the current user's domain.

    .EXAMPLE
    Get-DSLAPSCoverage -Domain 'contoso.com'

    Returns all enabled computer objects with their LAPS deployment status and risk level.

    .EXAMPLE
    Get-DSLAPSCoverage -Domain 'contoso.com' | Where-Object { -not $_.HasLAPS }

    Returns only computers that have no LAPS deployment.

    .NOTES
    #### Name:    Get-DSLAPSCoverage
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

        Write-Verbose "Querying domain: $DomainName for LAPS coverage"

        $ldapPath   = "LDAP://$DomainName"
        $ldapFilter = '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        $properties = @(
            'distinguishedName'
            'sAMAccountName'
            'name'
            'ms-Mcs-AdmPwd'
            'ms-Mcs-AdmPwdExpirationTime'
            'msLAPS-Password'
            'msLAPS-PasswordExpirationTime'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $queryResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($obj in $queryResults)
        {
            $legacyLapsPwd     = $obj['ms-mcs-admpwd']
            $legacyLapsExpiry  = $obj['ms-mcs-admpwdexpirationtime']
            $windowsLapsPwd    = $obj['mslaps-password']
            $windowsLapsExpiry = $obj['mslaps-passwordexpirationtime']

            $hasLegacyLAPS  = ($null -ne $legacyLapsPwd -and $legacyLapsPwd.Count -gt 0)
            $hasWindowsLAPS = ($null -ne $windowsLapsPwd -and $windowsLapsPwd.Count -gt 0)
            $hasAnyLAPS     = $hasLegacyLAPS -or $hasWindowsLAPS

            $lapsVersion = if ($hasWindowsLAPS) { 'WindowsLAPS' } elseif ($hasLegacyLAPS) { 'LegacyLAPS' } else { 'None' }

            # Check expiry
            $isExpired = $false
            if ($hasLegacyLAPS -and $null -ne $legacyLapsExpiry[0])
            {
                $expiryTime = [DateTime]::FromFileTime([long]$legacyLapsExpiry[0])
                $isExpired  = ($expiryTime -lt (Get-Date))
            }
            elseif ($hasWindowsLAPS -and $null -ne $windowsLapsExpiry[0])
            {
                $expiryTime = [DateTime]::FromFileTime([long]$windowsLapsExpiry[0])
                $isExpired  = ($expiryTime -lt (Get-Date))
            }

            # Parse OU from DN
            $dn = [string]$obj['distinguishedname'][0]
            $ou = if ($dn -match ',OU=') { ($dn -replace '^CN=[^,]+,', '') } else { 'root' }

            [void]$results.Add(
                [PSCustomObject]@{
                    Name              = [string]$obj['name'][0]
                    SamAccountName    = [string]$obj['samaccountname'][0]
                    DistinguishedName = $dn
                    OU                = $ou
                    LAPSVersion       = $lapsVersion
                    HasLAPS           = $hasAnyLAPS
                    IsExpired         = $isExpired
                    RiskLevel         = if (-not $hasAnyLAPS) { 'High' } elseif ($isExpired) { 'Medium' } else { 'Low' }
                }
            )
        }
    }

    End
    {
        $total     = $results.Count
        $covered   = ($results | Where-Object { $_.HasLAPS }).Count
        $uncovered = $total - $covered
        $expired   = ($results | Where-Object { $_.IsExpired }).Count

        Write-Verbose "LAPS Coverage: $covered/$total computers covered ($uncovered uncovered, $expired expired)"

        $results | Sort-Object -Property HasLAPS, IsExpired
    }
}
