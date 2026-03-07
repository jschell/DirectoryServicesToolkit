function Find-DSRODCCachedCredentials
{
<#
.SYNOPSIS
Identifies accounts whose credentials are currently cached on Read-Only Domain Controllers.

.DESCRIPTION
Queries the msDS-RevealedList attribute on each RODC computer object. This attribute
contains the distinguished names of user accounts whose password hashes have been
replicated to and are currently cached on the RODC.

If an RODC is physically compromised (theft, supply chain, third-party site), the
attacker gains access to the cached credentials. If any Tier 0 account (Domain Admins,
Enterprise Admins, krbtgt) credentials are cached, the compromise is domain-critical.

Risk assessment:
  - Tier 0 account credential cached on RODC → Critical
  - Privileged account (Administrators, Schema Admins) cached → High
  - Standard user account cached → Informational

Requires read access to the domain partition and the msDS-RevealedList attribute
on computer objects (readable by domain users by default in most environments).

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER HighlightTier0
When specified, only returns accounts flagged as Tier 0 or privileged. Use to quickly
surface the most critical cached credential findings.

.EXAMPLE
Find-DSRODCCachedCredentials -Domain 'contoso.com'

Returns all accounts with credentials currently cached on any RODC.

.EXAMPLE
Find-DSRODCCachedCredentials | Where-Object { $_.RiskLevel -eq 'Critical' }

Returns only Tier 0 accounts with credentials cached on an RODC.

.EXAMPLE
Find-DSRODCCachedCredentials -HighlightTier0

Returns only accounts whose credential caching is a Critical or High finding.

.NOTES
#### Name:    Find-DSRODCCachedCredentials
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-07::0.1.0
- Initial creation — msDS-RevealedList per RODC cached credential enumeration

.LINK
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc730883(v=ws.10)
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(HelpMessage = 'DNS name of the target domain')]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter(HelpMessage = 'Return only Critical and High risk cached accounts')]
        [switch]$HighlightTier0
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

        Write-Verbose "Querying domain: $DomainName for RODC cached credentials"

        $ldapPath = "LDAP://$DomainName"

        # Find all RODCs (primaryGroupID = 521)
        $rodcFilter     = '(&(objectClass=computer)(primaryGroupID=521))'
        $rodcProperties = @(
            'name'
            'distinguishedName'
            'dNSHostName'
            'msDS-RevealedList'
        )

        # Privileged name patterns for risk classification
        $tier0Patterns       = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'krbtgt')
        $privilegedPatterns  = @('Administrators', 'Account Operators', 'Backup Operators', 'Server Operators')

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $rodcs = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $rodcFilter -Properties $rodcProperties

        foreach ($rodc in $rodcs)
        {
            $rodcName = [string]$rodc['name'][0]
            $dnsHost  = if ($null -ne $rodc['dnshostname'][0]) { [string]$rodc['dnshostname'][0] } else { $rodcName }

            Write-Verbose "Reading msDS-RevealedList on RODC: $rodcName"

            $revealedList = if ($null -ne $rodc['msds-revealedlist'])
            {
                @($rodc['msds-revealedlist'] | ForEach-Object { [string]$_ })
            }
            else
            {
                @()
            }

            if ($revealedList.Count -eq 0)
            {
                Write-Verbose "No credentials cached on RODC '$rodcName'"
                continue
            }

            foreach ($cachedDN in $revealedList)
            {
                # Determine risk based on DN patterns (CN components)
                $isTier0 = $false
                $isPrivileged = $false

                foreach ($pattern in $tier0Patterns)
                {
                    if ($cachedDN -match [regex]::Escape($pattern))
                    {
                        $isTier0 = $true
                        break
                    }
                }

                if (-not $isTier0)
                {
                    foreach ($pattern in $privilegedPatterns)
                    {
                        if ($cachedDN -match [regex]::Escape($pattern))
                        {
                            $isPrivileged = $true
                            break
                        }
                    }
                }

                $riskLevel = if ($isTier0) { 'Critical' }
                             elseif ($isPrivileged) { 'High' }
                             else { 'Informational' }

                if ($HighlightTier0 -and $riskLevel -eq 'Informational')
                {
                    continue
                }

                # Extract CN (sAMAccountName-like display) from DN
                $accountCN = if ($cachedDN -match '^CN=([^,]+)')
                {
                    $matches[1]
                }
                else
                {
                    $cachedDN
                }

                $finding = if ($isTier0)
                {
                    "Critical: Tier 0 account '$accountCN' credentials cached on RODC '$rodcName' — RODC compromise = domain compromise"
                }
                elseif ($isPrivileged)
                {
                    "High: Privileged account '$accountCN' credentials cached on RODC '$rodcName'"
                }
                else
                {
                    $null
                }

                [void]$results.Add(
                    [PSCustomObject]@{
                        RODCName          = $rodcName
                        RODCHostName      = $dnsHost
                        CachedAccountDN   = $cachedDN
                        CachedAccountName = $accountCN
                        IsTier0           = $isTier0
                        IsPrivileged      = $isPrivileged
                        RiskLevel         = $riskLevel
                        Finding           = $finding
                    }
                )
            }
        }
    }

    End
    {
        $results | Sort-Object -Property RiskLevel, RODCName, CachedAccountName
    }
}
