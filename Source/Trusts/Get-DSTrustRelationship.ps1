function Get-DSTrustRelationship
{
<#
.SYNOPSIS
Enumerates all domain and forest trusts with detailed attribute information.

.DESCRIPTION
Returns all trust objects from the domain partition with full attribute
enumeration including:

  - Trust direction (Inbound, Outbound, Bidirectional)
  - Trust type (External, Forest, Realm, ParentChild, DownlevelNT, MITKerberos)
  - Transitivity (transitive vs non-transitive)
  - SID filtering / quarantine status (TRUST_ATTRIBUTE_QUARANTINED_DOMAIN)
  - TGT delegation blocking (TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION)
  - Forest transitivity flag (TRUST_ATTRIBUTE_FOREST_TRANSITIVE)
  - Target domain NetBIOS name and SID
  - Trust creation and modification timestamps

Trust objects are read from CN=System,<DomainDN> where objectClass=trustedDomain.
Use ConvertFrom-TrustAttributeValue on the TrustAttributes integer for a full
human-readable flag breakdown.

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeForest
When specified, also enumerates trusts from all other domains in the forest,
providing a forest-wide trust map. Each result is tagged with SourceDomain.

.EXAMPLE
Get-DSTrustRelationship -Domain 'contoso.com'

Returns all trusts for the contoso.com domain.

.EXAMPLE
Get-DSTrustRelationship -IncludeForest

Returns all trusts across every domain in the current forest.

.NOTES
#### Name:    Get-DSTrustRelationship
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
        [switch]$IncludeForest
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

        Write-Verbose "Querying domain: $DomainName for trust relationships"

        $domainDn = 'DC=' + ($DomainName -replace '\.', ',DC=')

        $trustProperties = @(
            'name'
            'trustDirection'
            'trustType'
            'trustAttributes'
            'securityIdentifier'
            'flatName'
            'whenCreated'
            'whenChanged'
        )
    }

    Process
    {
        # ── Query trusts for the primary domain ──────────────────────────────

        $trustResults = Get-DSTrustObjects -SystemDn "CN=System,$domainDn" `
            -Properties $trustProperties

        foreach ($obj in $trustResults)
        {
            ConvertTo-TrustObject -Obj $obj -SourceDomain $DomainName
        }

        # ── Optionally enumerate all forest domains ──────────────────────────

        if ($IncludeForest)
        {
            $forestDomains = $null
            try
            {
                $forest       = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
                $forestDomains = @($forest.Domains | ForEach-Object { $_.Name })
                $forest.Dispose()
            }
            catch
            {
                Write-Verbose "Could not enumerate forest domains: $_"
                return
            }

            foreach ($forestDomain in $forestDomains)
            {
                if ($forestDomain -eq $DomainName) { continue }

                $fDomainDn = 'DC=' + ($forestDomain -replace '\.', ',DC=')

                try
                {
                    $fTrustResults = Get-DSTrustObjects -SystemDn "CN=System,$fDomainDn" `
                        -Properties $trustProperties

                    foreach ($obj in $fTrustResults)
                    {
                        ConvertTo-TrustObject -Obj $obj -SourceDomain $forestDomain
                    }
                }
                catch
                {
                    Write-Verbose "Could not query trusts for forest domain '$forestDomain': $_"
                }
            }
        }
    }

    End {}
}


function Get-DSTrustObjects
{
<#
.SYNOPSIS
Internal helper — queries trustedDomain objects under a given CN=System DN.
#>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    Param
    (
        [Parameter(Mandatory)]
        [string]$SystemDn,

        [Parameter(Mandatory)]
        [string[]]$Properties
    )

    $ldapPath = "LDAP://$SystemDn"

    try
    {
        Invoke-DSDirectorySearch -LdapPath $ldapPath `
            -Filter '(objectClass=trustedDomain)' `
            -Properties $Properties
    }
    catch
    {
        Write-Verbose "Trust query failed for '$SystemDn': $_"
        return [hashtable[]]@()
    }
}


function ConvertTo-TrustObject
{
<#
.SYNOPSIS
Internal helper — converts a raw trust hashtable to the output PSCustomObject.
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory)]
        [hashtable]$Obj,

        [Parameter(Mandatory)]
        [string]$SourceDomain
    )

    $trustDirection  = [int]$Obj['trustdirection'][0]
    $trustType       = [int]$Obj['trusttype'][0]
    $trustAttributes = if ($Obj['trustattributes'] -and $Obj['trustattributes'].Count -gt 0)
                       { [int]$Obj['trustattributes'][0] } else { 0 }

    # Direction name
    $directionName = switch ($trustDirection)
    {
        1 { 'Inbound' }
        2 { 'Outbound' }
        3 { 'Bidirectional' }
        default { "Unknown($trustDirection)" }
    }

    # Trust type name — derived from trustType integer + key attribute flags
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

    # SID conversion from raw bytes
    $trustedSid = $null
    $sidRaw = $Obj['securityidentifier']
    if ($null -ne $sidRaw -and $sidRaw.Count -gt 0 -and $null -ne $sidRaw[0])
    {
        try
        {
            $sidBytes  = [byte[]]$sidRaw[0]
            $trustedSid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).ToString()
        }
        catch
        {
            Write-Verbose "Could not parse SID for trust '$([string]$Obj['name'][0])': $_"
        }
    }

    $whenCreatedRaw  = $Obj['whencreated']
    $whenChangedRaw  = $Obj['whenchanged']
    $flatNameRaw     = $Obj['flatname']

    $isSIDFiltered      = [bool]($trustAttributes -band 4)
    $isTGTBlocked       = [bool]($trustAttributes -band 512)
    $isTransitive       = -not [bool]($trustAttributes -band 1)
    $isForestTransitive = [bool]($trustAttributes -band 8)

    # RiskLevel: trusts without SID filtering enabled allow SID history attacks — an attacker
    # in the trusted domain can forge SID history entries for privileged groups in this domain.
    # Cross-forest or bidirectional transitive trusts without SID filtering are Critical.
    # Unidirectional trusts without SID filtering are High.
    # Transitive trusts with TGT delegation not blocked allow unconstrained delegation across
    # the trust boundary — High when not blocked.
    # All other trusts are Informational (expected in multi-domain forests).
    $trustRiskLevel = if (-not $isSIDFiltered -and ($isForestTransitive -or $directionName -eq 'Bidirectional')) { 'Critical' }
                     elseif (-not $isSIDFiltered) { 'High' }
                     elseif ($isTransitive -and -not $isTGTBlocked) { 'High' }
                     else { 'Informational' }

    [PSCustomObject]@{
        Name                  = [string]$Obj['name'][0]
        FlatName              = if ($flatNameRaw -and $flatNameRaw.Count -gt 0) { [string]$flatNameRaw[0] } else { $null }
        TrustedDomainSID      = $trustedSid
        Direction             = $directionName
        TrustType             = $typeName
        IsTransitive          = $isTransitive
        ForestTransitive      = $isForestTransitive
        SIDFilteringEnabled   = $isSIDFiltered
        TGTDelegationBlocked  = $isTGTBlocked
        WithinForest          = [bool]($trustAttributes -band 32)
        TreatAsExternal       = [bool]($trustAttributes -band 64)
        TrustAttributes       = $trustAttributes
        WhenCreated           = if ($whenCreatedRaw -and $whenCreatedRaw.Count -gt 0) { $whenCreatedRaw[0] } else { $null }
        WhenModified          = if ($whenChangedRaw -and $whenChangedRaw.Count -gt 0) { $whenChangedRaw[0] } else { $null }
        SourceDomain          = $SourceDomain
        RiskLevel             = $trustRiskLevel
    }
}
