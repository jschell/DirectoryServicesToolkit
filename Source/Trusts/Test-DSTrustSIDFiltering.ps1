function Test-DSTrustSIDFiltering
{
<#
.SYNOPSIS
Validates whether SID filtering (quarantine) is enforced on each trust.

.DESCRIPTION
Tests each trust relationship in the domain and returns whether SID filtering
(also known as SID quarantine) is enforced via the
TRUST_ATTRIBUTE_QUARANTINED_DOMAIN flag (trustAttributes bit 4).

When SID filtering is disabled on an inter-forest or external trust, an
attacker who compromises the trusted domain can insert SIDs from the trusting
domain's privileged groups into their Kerberos tokens via SID history
(msDS-SidHistory). This is a well-known privilege escalation path between
forests when SID filtering is absent.

Filtering status is assessed as follows:
  Enabled      — QUARANTINED_DOMAIN bit explicitly set; SID filtering enforced
  ForestDefault — Forest trust without explicit quarantine; forest boundary
                  provides isolation but SID history from within-forest domains
                  is not blocked
  WithinForest — Parent/child or shortcut trust; SID filtering always on
                 within a forest and cannot be disabled
  Disabled     — External trust without quarantine; SID history attacks possible
                 (High risk)

Note: SID filtering is always enforced within a forest between parent and
child domains; this test is most relevant for external and forest trusts.

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Test-DSTrustSIDFiltering -Domain 'contoso.com'

Returns all trusts with their SID filtering status. Trusts without SID
filtering are flagged as High risk.

.NOTES
#### Name:    Test-DSTrustSIDFiltering
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
        [string]$Domain = $env:USERDNSDOMAIN
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

        Write-Verbose "Querying domain: $DomainName for SID filtering status"

        $domainDn = 'DC=' + ($DomainName -replace '\.', ',DC=')

        $trustProperties = @(
            'name'
            'trustDirection'
            'trustType'
            'trustAttributes'
            'flatName'
        )
    }

    Process
    {
        $ldapPath    = "LDAP://CN=System,$domainDn"
        $trustFilter = '(objectClass=trustedDomain)'

        $trustResults = $null
        try
        {
            $trustResults = Invoke-DSDirectorySearch -LdapPath $ldapPath `
                -Filter $trustFilter -Properties $trustProperties
        }
        catch
        {
            Write-Error "Failed to query trusts: $_"
            return
        }

        Write-Verbose "Evaluating SID filtering on $($trustResults.Count) trust(s)"

        foreach ($obj in $trustResults)
        {
            $trustName       = [string]$obj['name'][0]
            $trustDirection  = [int]$obj['trustdirection'][0]
            $trustType       = [int]$obj['trusttype'][0]
            $trustAttributes = if ($obj['trustattributes'] -and $obj['trustattributes'].Count -gt 0)
                               { [int]$obj['trustattributes'][0] } else { 0 }

            # Direction name
            $directionName = switch ($trustDirection)
            {
                1 { 'Inbound' }
                2 { 'Outbound' }
                3 { 'Bidirectional' }
                default { "Unknown($trustDirection)" }
            }

            # Trust type name
            $typeName = switch ($trustType)
            {
                1 { 'DownlevelNT' }
                2
                {
                    if ($trustAttributes -band 8)       { 'Forest' }
                    elseif ($trustAttributes -band 32)  { 'ParentChild' }
                    elseif ($trustAttributes -band 64)  { 'External' }
                    else                                { 'External' }
                }
                3 { 'MITKerberos' }
                4 { 'DCE' }
                default { "Unknown($trustType)" }
            }

            # ── SID filtering status logic ────────────────────────────────────

            $sidFilteringEnabled = [bool]($trustAttributes -band 4)   # QUARANTINED_DOMAIN
            $isForestTrust       = [bool]($trustAttributes -band 8)   # FOREST_TRANSITIVE
            $isWithinForest      = [bool]($trustAttributes -band 32)  # WITHIN_FOREST

            $filteringStatus = if ($sidFilteringEnabled)
            {
                'Enabled'
            }
            elseif ($isWithinForest)
            {
                'WithinForest'
            }
            elseif ($isForestTrust)
            {
                'ForestDefault'
            }
            else
            {
                'Disabled'
            }

            $riskLevel = switch ($filteringStatus)
            {
                'Enabled'       { 'Low' }
                'WithinForest'  { 'Low' }
                'ForestDefault' { 'Medium' }
                'Disabled'      { 'High' }
                default         { 'Unknown' }
            }

            [PSCustomObject]@{
                TrustName           = $trustName
                Direction           = $directionName
                TrustType           = $typeName
                SIDFilteringEnabled = $sidFilteringEnabled
                FilteringStatus     = $filteringStatus
                RiskLevel           = $riskLevel
                TrustAttributes     = $trustAttributes
            }
        }
    }

    End {}
}
