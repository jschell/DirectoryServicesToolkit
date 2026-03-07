function Find-DSStaleAccounts
{
<#
.SYNOPSIS
Finds enabled user and computer accounts that have not authenticated recently.

.DESCRIPTION
Returns enabled accounts whose lastLogonTimestamp is older than the specified
threshold. Uses the replicated lastLogonTimestamp attribute, which is updated
when an account authenticates and is replicated to all DCs (with up to ~14 day
accuracy due to the replication delay configured by the msDS-LogonTimeSyncInterval
attribute, typically 14 days).

Also includes enabled accounts that have never logged on (lastLogonTimestamp
absent or 0), which are stale by definition.

For the most accurate single-account last logon, use Get-LastLoginInDomain,
which queries all DCs for the non-replicated lastlogon attribute.

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER ThresholdDays
Number of days of inactivity after which an account is considered stale.
Defaults to 90.

.PARAMETER ObjectType
The type of objects to enumerate: User, Computer, or All. Defaults to All.

.PARAMETER SearchBase
The distinguished name of the OU or container to limit the search to.

.EXAMPLE
Find-DSStaleAccounts -Domain 'contoso.com'

Returns all enabled users and computers with no authentication in 90+ days.

.EXAMPLE
Find-DSStaleAccounts -ThresholdDays 180 -ObjectType User

Returns enabled user accounts inactive for 180 or more days.

.NOTES
#### Name:    Find-DSStaleAccounts
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
        [ValidateRange(1, 3650)]
        [int]$ThresholdDays = 90,

        [Parameter()]
        [ValidateSet('User', 'Computer', 'All')]
        [string]$ObjectType = 'All',

        [Parameter()]
        [string]$SearchBase
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

        Write-Verbose "Querying domain: $DomainName for stale accounts (threshold: $ThresholdDays days)"

        $ldapPath = if ($SearchBase)
        {
            "LDAP://$SearchBase"
        }
        else
        {
            "LDAP://$DomainName"
        }

        $thresholdDate     = (Get-Date).AddDays(-$ThresholdDays)
        $thresholdFileTime = $thresholdDate.ToFileTime()

        Write-Verbose "Threshold FILETIME: $thresholdFileTime ($thresholdDate)"

        $properties = @(
            'distinguishedName'
            'sAMAccountName'
            'userAccountControl'
            'lastLogonTimestamp'
            'pwdLastSet'
            'objectClass'
        )

        # Deduplicate (never-logged-on query may overlap with timestamp query)
        $seen = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $now = Get-Date

        # ── Users ─────────────────────────────────────────────────────────────

        if ($ObjectType -eq 'All' -or $ObjectType -eq 'User')
        {
            # Users with lastLogonTimestamp beyond threshold
            $userFilter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$thresholdFileTime))"
            Write-Verbose "User stale filter: $userFilter"

            $userResults = Invoke-DSDirectorySearch -LdapPath $ldapPath `
                -Filter $userFilter -Properties $properties

            foreach ($obj in $userResults)
            {
                $dn = [string]$obj['distinguishedname'][0]
                if (-not $seen.Add($dn)) { continue }
                [void]$results.Add((Build-StaleAccountObject $obj $now 'User'))
            }

            # Users that have never logged on
            $neverFilter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(lastLogonTimestamp=*)))'
            Write-Verbose "User never-logged-on filter: $neverFilter"

            $neverResults = Invoke-DSDirectorySearch -LdapPath $ldapPath `
                -Filter $neverFilter -Properties $properties

            foreach ($obj in $neverResults)
            {
                $dn = [string]$obj['distinguishedname'][0]
                if (-not $seen.Add($dn)) { continue }
                [void]$results.Add((Build-StaleAccountObject $obj $now 'User'))
            }
        }

        # ── Computers ─────────────────────────────────────────────────────────

        if ($ObjectType -eq 'All' -or $ObjectType -eq 'Computer')
        {
            # Computers with lastLogonTimestamp beyond threshold
            $compFilter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$thresholdFileTime))"
            Write-Verbose "Computer stale filter: $compFilter"

            $compResults = Invoke-DSDirectorySearch -LdapPath $ldapPath `
                -Filter $compFilter -Properties $properties

            foreach ($obj in $compResults)
            {
                $dn = [string]$obj['distinguishedname'][0]
                if (-not $seen.Add($dn)) { continue }
                [void]$results.Add((Build-StaleAccountObject $obj $now 'Computer'))
            }

            # Computers that have never logged on
            $compNeverFilter = '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(lastLogonTimestamp=*)))'
            Write-Verbose "Computer never-logged-on filter: $compNeverFilter"

            $compNeverResults = Invoke-DSDirectorySearch -LdapPath $ldapPath `
                -Filter $compNeverFilter -Properties $properties

            foreach ($obj in $compNeverResults)
            {
                $dn = [string]$obj['distinguishedname'][0]
                if (-not $seen.Add($dn)) { continue }
                [void]$results.Add((Build-StaleAccountObject $obj $now 'Computer'))
            }
        }
    }

    End
    {
        $results | Sort-Object -Property DaysSinceLastLogon -Descending
    }
}


function Build-StaleAccountObject
{
<#
.SYNOPSIS
Internal helper — constructs a stale account output object from a raw ADSI result.
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory)]
        [hashtable]$Obj,

        [Parameter(Mandatory)]
        [DateTime]$Now,

        [Parameter(Mandatory)]
        [string]$Type
    )

    $uac = [int]$Obj['useraccountcontrol'][0]

    $lastLogonRaw = $Obj['lastlogontimestamp'][0]
    if ($null -ne $lastLogonRaw -and [long]$lastLogonRaw -gt 0)
    {
        $lastLogon         = [DateTime]::FromFileTime([long]$lastLogonRaw)
        $daysSinceLastLogon = [int]($Now - $lastLogon).TotalDays
    }
    else
    {
        $lastLogon         = $null
        $daysSinceLastLogon = $null
    }

    $pwdLastSetRaw = $Obj['pwdlastset'][0]
    $passwordLastSet = if ($null -ne $pwdLastSetRaw -and [long]$pwdLastSetRaw -gt 0)
    {
        [DateTime]::FromFileTime([long]$pwdLastSetRaw)
    }
    else
    {
        $null
    }

    # RiskLevel: accounts that have never logged on or have been inactive for over a year are
    # likely orphaned — a higher risk because they may retain broad permissions and their
    # credentials may never have been rotated. Moderately stale accounts are Medium.
    $staleRiskLevel = if ($null -eq $daysSinceLastLogon) { 'High' }
                     elseif ($daysSinceLastLogon -ge 365) { 'High' }
                     else { 'Medium' }

    [PSCustomObject]@{
        SamAccountName     = [string]$Obj['samaccountname'][0]
        DistinguishedName  = [string]$Obj['distinguishedname'][0]
        ObjectType         = $Type
        Enabled            = -not [bool]($uac -band 2)
        LastLogonTimestamp = $lastLogon
        DaysSinceLastLogon = $daysSinceLastLogon
        PasswordLastSet    = $passwordLastSet
        RiskLevel          = $staleRiskLevel
    }
}
