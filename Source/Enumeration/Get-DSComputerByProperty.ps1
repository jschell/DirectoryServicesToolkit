function Get-DSComputerByProperty
{
<#
.SYNOPSIS
Searches Active Directory for computer objects by configurable properties.

.DESCRIPTION
Computer-object equivalent of Get-DSUserByProperty. Queries AD for computer
accounts matching criteria across common properties including OS version,
last logon timestamp, enabled state, and OU location.

Uses System.DirectoryServices for queries; no RSAT dependency.

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER OperatingSystem
Filter by operating system name string. Supports wildcards (e.g. 'Windows Server 2016*').

.PARAMETER SearchBase
The distinguished name of the OU or container to limit the search to.

.PARAMETER Enabled
When $true, returns only enabled computer accounts. When $false, returns only
disabled accounts. When not specified, returns both.

.PARAMETER InactiveDays
Returns computers whose lastLogonTimestamp is older than this many days.
Uses the replicated lastLogonTimestamp attribute (~14 day accuracy).

.PARAMETER SizeLimit
Maximum number of results to return. Defaults to 0 (unlimited).

.EXAMPLE
Get-DSComputerByProperty -Domain 'contoso.com' -OperatingSystem 'Windows Server 2012*'

Returns all computers running Windows Server 2012 or 2012 R2.

.EXAMPLE
Get-DSComputerByProperty -InactiveDays 90 -Enabled $true

Returns enabled computers with no logon activity in the past 90 days.

.NOTES
#### Name:    Get-DSComputerByProperty
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-03::0.1.0
- Initial creation
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter()]
        [string]$OperatingSystem,

        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [nullable[bool]]$Enabled,

        [Parameter()]
        [ValidateRange(0, 3650)]
        [int]$InactiveDays,

        [Parameter()]
        [ValidateRange(0, 10000)]
        [int]$SizeLimit = 0
    )

    Begin
    {
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)

        try
        {
            $DomainEntry = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $DomainName  = $DomainEntry.Name
            $DomainEntry.Dispose()
        }
        catch
        {
            Write-Error "Cannot connect to domain '$Domain': $_"
            return
        }

        Write-Verbose "Querying domain: $DomainName for computer objects"

        $ldapPath = if ($SearchBase)
        {
            "LDAP://$SearchBase"
        }
        else
        {
            "LDAP://$DomainName"
        }

        # ── Build LDAP filter dynamically ────────────────────────────────────

        $filterParts = @('(objectCategory=computer)')

        if ($OperatingSystem)
        {
            $filterParts += "(operatingSystem=$OperatingSystem)"
        }

        if ($null -ne $Enabled)
        {
            if ($Enabled -eq $true)
            {
                $filterParts += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
            }
            else
            {
                $filterParts += '(userAccountControl:1.2.840.113556.1.4.803:=2)'
            }
        }

        if ($InactiveDays -gt 0)
        {
            $threshold     = (Get-Date).AddDays(-$InactiveDays).ToFileTime()
            $filterParts  += "(lastLogonTimestamp<=$threshold)"
        }

        $ldapFilter = if ($filterParts.Count -eq 1)
        {
            $filterParts[0]
        }
        else
        {
            '(&{0})' -f ($filterParts -join '')
        }

        Write-Verbose "LDAP filter: $ldapFilter"

        $properties = @(
            'name'
            'sAMAccountName'
            'distinguishedName'
            'operatingSystem'
            'operatingSystemVersion'
            'userAccountControl'
            'lastLogonTimestamp'
            'pwdLastSet'
            'dNSHostName'
        )
    }

    Process
    {
        $queryResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter `
            -Properties $properties -SizeLimit $SizeLimit

        Write-Verbose "Processing $($queryResults.Count) computer objects"

        $now = Get-Date

        foreach ($obj in $queryResults)
        {
            $uac = [int]$obj['useraccountcontrol'][0]

            $pwdLastSetRaw = $obj['pwdlastset'][0]
            $passwordLastSet = if ($null -ne $pwdLastSetRaw -and [long]$pwdLastSetRaw -gt 0)
            {
                [DateTime]::FromFileTime([long]$pwdLastSetRaw)
            }
            else
            {
                $null
            }

            $lastLogonRaw = $obj['lastlogontimestamp'][0]
            $lastLogon = if ($null -ne $lastLogonRaw -and [long]$lastLogonRaw -gt 0)
            {
                [DateTime]::FromFileTime([long]$lastLogonRaw)
            }
            else
            {
                $null
            }

            $daysSinceLastLogon = if ($null -ne $lastLogon)
            {
                [int]($now - $lastLogon).TotalDays
            }
            else
            {
                $null
            }

            $osRaw      = $obj['operatingsystem']
            $osVerRaw   = $obj['operatingsystemversion']
            $dnsRaw     = $obj['dnshostname']

            [PSCustomObject]@{
                Name                   = [string]$obj['name'][0]
                SamAccountName         = [string]$obj['samaccountname'][0]
                DistinguishedName      = [string]$obj['distinguishedname'][0]
                DNSHostName            = if ($dnsRaw -and $dnsRaw.Count -gt 0) { [string]$dnsRaw[0] } else { $null }
                OperatingSystem        = if ($osRaw -and $osRaw.Count -gt 0) { [string]$osRaw[0] } else { $null }
                OperatingSystemVersion = if ($osVerRaw -and $osVerRaw.Count -gt 0) { [string]$osVerRaw[0] } else { $null }
                Enabled                = -not [bool]($uac -band 2)
                PasswordLastSet        = $passwordLastSet
                LastLogonTimestamp     = $lastLogon
                DaysSinceLastLogon     = $daysSinceLastLogon
            }
        }
    }

    End {}
}
