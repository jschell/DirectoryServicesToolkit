function Get-DSRODCConfig
{
<#
.SYNOPSIS
Enumerates Read-Only Domain Controllers and their Password Replication Policy groups.

.DESCRIPTION
Queries all Read-Only Domain Controllers (primaryGroupID=521) in the domain and
returns their Password Replication Policy (PRP) group membership configuration.

The PRP controls which accounts' credentials may be cached on the RODC:
  msDS-RevealOnDemandGroup — Allowed PRP: accounts in these groups are eligible for
                             credential caching on demand.
  msDS-NeverRevealGroup    — Denied PRP: accounts in these groups are explicitly
                             excluded from credential caching (takes precedence over Allowed).

Risk flags:
  - Any Tier 0 account (Domain Admins, Enterprise Admins, krbtgt) present in the
    Allowed PRP list is a Critical finding — if the RODC is compromised, the cached
    credentials can be harvested to compromise the parent domain.
  - A Denied PRP that does not include 'Denied RODC Password Replication Group' is a
    High finding — the default deny list should always be present.

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Get-DSRODCConfig -Domain 'contoso.com'

Returns configuration for all RODCs in the contoso.com domain.

.EXAMPLE
Get-DSRODCConfig | Where-Object { $_.AllowedPRPGroups.Count -gt 0 }

Returns RODCs that have an explicit Allowed PRP configured.

.NOTES
#### Name:    Get-DSRODCConfig
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-07::0.1.0
- Initial creation — RODC PRP group enumeration

.LINK
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc730883(v=ws.10)
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

        Write-Verbose "Querying domain: $DomainName for Read-Only Domain Controllers"

        $ldapPath = "LDAP://$DomainName"

        # primaryGroupID 521 = Read-Only Domain Controllers built-in group RID
        $ldapFilter = '(&(objectClass=computer)(primaryGroupID=521))'
        $properties = @(
            'name'
            'distinguishedName'
            'dNSHostName'
            'msDS-RevealOnDemandGroup'
            'msDS-NeverRevealGroup'
            'operatingSystem'
            'operatingSystemVersion'
            'whenCreated'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $rodcs = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($obj in $rodcs)
        {
            $rodcName  = [string]$obj['name'][0]
            $dnsHost   = if ($null -ne $obj['dnshostname'][0]) { [string]$obj['dnshostname'][0] } else { $rodcName }
            $os        = if ($null -ne $obj['operatingsystem'][0]) { [string]$obj['operatingsystem'][0] } else { $null }
            $osVersion = if ($null -ne $obj['operatingsystemversion'][0]) { [string]$obj['operatingsystemversion'][0] } else { $null }

            $whenCreatedRaw = $obj['whencreated'][0]
            $whenCreated = if ($null -ne $whenCreatedRaw)
            {
                try { [DateTime]$whenCreatedRaw } catch { $null }
            }
            else
            {
                $null
            }

            # Allowed PRP: msDS-RevealOnDemandGroup — multi-value attribute, each value is a DN
            $allowedPRP = if ($null -ne $obj['msds-revealondemandgroup'])
            {
                @($obj['msds-revealondemandgroup'] | ForEach-Object { [string]$_ })
            }
            else
            {
                @()
            }

            # Denied PRP: msDS-NeverRevealGroup — multi-value attribute, each value is a DN
            $deniedPRP = if ($null -ne $obj['msds-neverrevealgroup'])
            {
                @($obj['msds-neverrevealgroup'] | ForEach-Object { [string]$_ })
            }
            else
            {
                @()
            }

            # Risk assessment
            # Check if default deny group is present
            $hasDeniedRODCGroup = $deniedPRP | Where-Object { $_ -match 'Denied RODC Password Replication Group' }
            $missingDefaultDeny = ($null -eq $hasDeniedRODCGroup -or @($hasDeniedRODCGroup).Count -eq 0)

            # Flag if any Tier 0 group names appear in the Allowed PRP
            $tier0Patterns = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'krbtgt')
            $allowedTier0 = @($allowedPRP | Where-Object {
                $dn = $_
                $tier0Patterns | Where-Object { $dn -match $_ }
            })

            $riskLevel = if ($allowedTier0.Count -gt 0)
            {
                'Critical'
            }
            elseif ($missingDefaultDeny)
            {
                'High'
            }
            else
            {
                'Informational'
            }

            $finding = if ($allowedTier0.Count -gt 0)
            {
                "RODC '$rodcName' Allowed PRP contains Tier 0 group(s): $($allowedTier0 -join '; ')"
            }
            elseif ($missingDefaultDeny)
            {
                "RODC '$rodcName' Denied PRP does not include the default 'Denied RODC Password Replication Group'"
            }
            else
            {
                $null
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    Name               = $rodcName
                    DNSHostName        = $dnsHost
                    DistinguishedName  = [string]$obj['distinguishedname'][0]
                    OperatingSystem    = $os
                    OSVersion          = $osVersion
                    WhenCreated        = $whenCreated
                    AllowedPRPGroups   = $allowedPRP
                    DeniedPRPGroups    = $deniedPRP
                    MissingDefaultDeny = $missingDefaultDeny
                    Tier0InAllowedPRP  = $allowedTier0.Count -gt 0
                    RiskLevel          = $riskLevel
                    Finding            = $finding
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property RiskLevel, Name
    }
}
