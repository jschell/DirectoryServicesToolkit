function Find-DSDCSyncRights
{
    <#
    .SYNOPSIS
    Identifies principals with DCSync replication rights on the domain naming context root.

    .DESCRIPTION
    Reads the ACL on the domain NC root object and flags any principal outside of well-known
    legitimate groups that holds DS-Replication-Get-Changes, DS-Replication-Get-Changes-All,
    or DS-Replication-Get-Changes-In-Filtered-Set rights. These rights, when combined, allow
    an attacker to request replication of all domain objects including password hashes (DCSync
    attack). Any non-expected principal with DS-Replication-Get-Changes-All is a critical
    finding. Requires read access to the domain partition and the ability to read AD object ACLs.

    .PARAMETER Domain
    The DNS name of the domain to query. Defaults to the current user's domain.

    .EXAMPLE
    Find-DSDCSyncRights -Domain 'contoso.com'

    Returns all non-legitimate principals holding replication rights on the domain NC root.

    .EXAMPLE
    Find-DSDCSyncRights -Domain 'contoso.com' | Where-Object { $_.IsCritical }

    Returns only critical findings where DS-Replication-Get-Changes-All is granted.

    .NOTES
    #### Name:    Find-DSDCSyncRights
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

        Write-Verbose "Checking DCSync rights on domain NC root: $DomainName"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $ldapPath = "LDAP://$domainDN"

        # Replication right GUIDs
        $syncRights = @{
            'DS-Replication-Get-Changes'                 = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            'DS-Replication-Get-Changes-All'             = [guid]'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
            'DS-Replication-Get-Changes-In-Filtered-Set' = [guid]'89e95b76-444d-4c62-991a-0facbeda640c'
        }

        # Principals that legitimately hold replication rights
        $legitimatePrincipals = @(
            'Domain Controllers'
            'Enterprise Domain Controllers'
            'Domain Admins'
            'Enterprise Admins'
            'Administrators'
            'BUILTIN\Administrators'
            'NT AUTHORITY\SYSTEM'
            'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $aces = Get-DSObjectAcl -LdapPath $ldapPath

        foreach ($ace in $aces)
        {
            if ($ace.AccessControlType -ne 'Allow') { continue }

            $matchedRight = $null
            foreach ($rightName in $syncRights.Keys)
            {
                if ($ace.ObjectType -eq $syncRights[$rightName])
                {
                    $matchedRight = $rightName
                    break
                }
            }

            if ($null -eq $matchedRight) { continue }

            # Resolve identity
            $identity = $ace.IdentityReference

            # Skip MSOL_ accounts (Azure AD Connect)
            if ($identity -match 'MSOL_') { continue }

            # Check if legitimate
            $isLegitimate = $false
            foreach ($principal in $legitimatePrincipals)
            {
                if ($identity -match [regex]::Escape($principal))
                {
                    $isLegitimate = $true
                    break
                }
            }

            if ($isLegitimate) { continue }

            $isCritical = ($matchedRight -eq 'DS-Replication-Get-Changes-All')

            [void]$results.Add(
                [PSCustomObject]@{
                    IdentityReference  = $identity
                    Right              = $matchedRight
                    RightGuid          = $ace.ObjectType.ToString()
                    IsInherited        = $ace.IsInherited
                    IsCritical         = $isCritical
                    RiskLevel          = if ($isCritical) { 'Critical' } else { 'High' }
                    Finding            = "Non-privileged principal '$identity' holds '$matchedRight' on domain NC root — potential DCSync capability"
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property IsCritical -Descending
    }
}
