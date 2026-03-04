function Get-DSGPO
{
<#
.SYNOPSIS
Enumerates Group Policy Objects with their links, scope, and inheritance status.

.DESCRIPTION
Returns all Group Policy Objects in the domain along with their:

  - Link locations (which OUs/domain they are linked to)
  - Link enforcement and enabled status
  - Inheritance blocking status on linked OUs
  - GPO enabled/disabled status (user portion, computer portion, or both)
  - Creation and modification timestamps
  - WMI filter associations

Flags GPOs linked at high-value OUs (Domain Controllers, AdminWorkstations)
and unlinked GPOs that are configured but never applied.

The two-pass approach first enumerates all groupPolicyContainer objects under
CN=Policies,CN=System,<DomainDN>, then parses gpLink attributes on all OUs and
the domain object to build the full link map.

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER LinkedOnly
When specified, returns only GPOs that have at least one active link.

.PARAMETER HighValueOUsOnly
When specified, returns only GPOs linked to Domain Controllers OU or OUs
whose name matches common admin workstation patterns.

.EXAMPLE
Get-DSGPO -Domain 'contoso.com'

Returns all GPOs in the domain with their link and status details.

.EXAMPLE
Get-DSGPO -LinkedOnly

Returns only GPOs that are actively linked to at least one location.

.NOTES
#### Name:    Get-DSGPO
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
        [switch]$LinkedOnly,

        [Parameter()]
        [switch]$HighValueOUsOnly
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

        Write-Verbose "Querying domain: $DomainName for GPOs"

        # Build domain DN from DNS name  (contoso.com → DC=contoso,DC=com)
        $domainDn = 'DC=' + ($DomainName -replace '\.', ',DC=')

        $ldapPath = "LDAP://$DomainName"

        # ── Pass 1: Enumerate all GPOs ────────────────────────────────────────

        $gpoPoliciesPath = "LDAP://CN=Policies,CN=System,$domainDn"
        $gpoFilter       = '(objectClass=groupPolicyContainer)'
        $gpoProperties   = @(
            'displayName'
            'cn'
            'gPCFileSysPath'
            'gPCFunctionalityVersion'
            'versionNumber'
            'whenCreated'
            'whenChanged'
            'flags'
            'gPCWQLFilter'
        )

        $gpoRaw = Invoke-DSDirectorySearch -LdapPath $gpoPoliciesPath `
            -Filter $gpoFilter -Properties $gpoProperties

        Write-Verbose "Found $($gpoRaw.Count) GPO objects"

        # Build GPO map: GUID (lowercase, with braces) → working object
        # $gpoMap['{guid}'] = @{ Raw = ...; Links = [List] }
        $gpoMap = @{}

        foreach ($g in $gpoRaw)
        {
            $cnRaw = $g['cn']
            $cn    = if ($cnRaw -and $cnRaw.Count -gt 0) { [string]$cnRaw[0] } else { $null }
            if (-not $cn) { continue }

            $gpoMap[$cn.ToLower()] = [PSCustomObject]@{
                Raw   = $g
                Links = [System.Collections.Generic.List[object]]::new()
            }
        }

        # ── Pass 2: Parse gpLink on domain and all OUs ────────────────────────

        $linkFilter     = '(gpLink=*)'
        $linkProperties = @('distinguishedName', 'gpLink', 'gpOptions')

        $linkObjects = Invoke-DSDirectorySearch -LdapPath $ldapPath `
            -Filter $linkFilter -Properties $linkProperties

        Write-Verbose "Found $($linkObjects.Count) objects with gpLink"

        # gpLink value format: [LDAP://cn={GUID},cn=policies,cn=system,...;N][...]
        $gpLinkPattern = '\[LDAP://[^;]+cn=(\{[^}]+\})[^;]*;(\d+)\]'

        foreach ($linkObj in $linkObjects)
        {
            $containerDn   = [string]$linkObj['distinguishedname'][0]
            $gpLinkRaw     = $linkObj['gplink']
            $gpOptionsRaw  = $linkObj['gpoptions']
            $inheritBlocked = ($null -ne $gpOptionsRaw -and $gpOptionsRaw.Count -gt 0 -and [int]$gpOptionsRaw[0] -eq 1)

            if (-not $gpLinkRaw -or $gpLinkRaw.Count -eq 0) { continue }

            $gpLinkStr = [string]$gpLinkRaw[0]

            $matches2 = [regex]::Matches($gpLinkStr, $gpLinkPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

            foreach ($m in $matches2)
            {
                $gpoGuid    = $m.Groups[1].Value.ToLower()
                $linkOption = [int]$m.Groups[2].Value

                # linkOption bitmask: bit 0 = link disabled, bit 1 = enforced
                $linkEnabled  = -not [bool]($linkOption -band 1)
                $linkEnforced = [bool]($linkOption -band 2)

                if ($gpoMap.ContainsKey($gpoGuid))
                {
                    [void]$gpoMap[$gpoGuid].Links.Add([PSCustomObject]@{
                        LinkedTo           = $containerDn
                        LinkEnabled        = $linkEnabled
                        LinkEnforced       = $linkEnforced
                        InheritanceBlocked = $inheritBlocked
                    })
                }
            }
        }
    }

    Process
    {
        # High-value OU patterns
        $highValuePatterns = @(
            'Domain Controllers'
            'AdminWorkstations'
            'AdminWorkstation'
            'PAW'
            'PrivilegedAccess'
            'Tier0'
            'Tier 0'
        )

        foreach ($gpoGuid in $gpoMap.Keys)
        {
            $entry  = $gpoMap[$gpoGuid]
            $g      = $entry.Raw
            $links  = @($entry.Links)
            $isLinked = $links.Count -gt 0

            # Apply -LinkedOnly filter
            if ($LinkedOnly -and -not $isLinked) { continue }

            # Apply -HighValueOUsOnly filter
            if ($HighValueOUsOnly)
            {
                $hasHighValue = $false
                foreach ($link in $links)
                {
                    foreach ($pattern in $highValuePatterns)
                    {
                        if ($link.LinkedTo -match [regex]::Escape($pattern))
                        {
                            $hasHighValue = $true
                            break
                        }
                    }
                    if ($hasHighValue) { break }
                }
                if (-not $hasHighValue) { continue }
            }

            # Parse GPO flags (enabled/disabled status)
            $flagsRaw = $g['flags']
            $gpoFlags = if ($flagsRaw -and $flagsRaw.Count -gt 0) { [int]$flagsRaw[0] } else { 0 }
            # bit 0 = user config disabled; bit 1 = computer config disabled
            $userSettingsEnabled     = -not [bool]($gpoFlags -band 1)
            $computerSettingsEnabled = -not [bool]($gpoFlags -band 2)

            $displayNameRaw = $g['displayname']
            $displayName    = if ($displayNameRaw -and $displayNameRaw.Count -gt 0) { [string]$displayNameRaw[0] } else { $null }

            $whenCreatedRaw  = $g['whencreated']
            $whenChangedRaw  = $g['whenchanged']
            $whenCreated     = if ($whenCreatedRaw -and $whenCreatedRaw.Count -gt 0) { $whenCreatedRaw[0] } else { $null }
            $whenModified    = if ($whenChangedRaw -and $whenChangedRaw.Count -gt 0) { $whenChangedRaw[0] } else { $null }

            $wmiFilterRaw = $g['gpcwqlfilter']
            $wmiFilter    = if ($wmiFilterRaw -and $wmiFilterRaw.Count -gt 0) { [string]$wmiFilterRaw[0] } else { $null }

            [PSCustomObject]@{
                DisplayName              = $displayName
                GPOId                    = $gpoGuid.ToUpper()
                WhenCreated              = $whenCreated
                WhenModified             = $whenModified
                UserSettingsEnabled      = $userSettingsEnabled
                ComputerSettingsEnabled  = $computerSettingsEnabled
                WMIFilter                = $wmiFilter
                Links                    = $links
                IsLinked                 = $isLinked
            }
        }
    }

    End {}
}
