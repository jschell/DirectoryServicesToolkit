function Find-DSADIDNSRecord
{
<#
.SYNOPSIS
Enumerates AD-Integrated DNS zone records that non-privileged users can modify.

.DESCRIPTION
AD-Integrated DNS stores zone data as objects in the domain partition under
DC=DomainDnsZones or DC=ForestDnsZones. By default, the Authenticated Users
or Everyone group may have Create Child rights on DNS zone objects, allowing
any domain user to add new DNS records — including overriding non-existent
hostnames used by high-value services.

This function enumerates DACL entries on DNS zone objects and identifies:

  - Containers where non-privileged principals have CreateChild, WriteProperty,
    GenericWrite, or GenericAll rights (ADIDNS hijacking surface)
  - The wildcard dnsNode record (*) if present in any zone — commonly added
    by attackers to intercept all unresolved DNS queries in the zone

The following principals are considered privileged and excluded from results:
  SYSTEM, Administrators, Domain Admins, Enterprise Admins,
  Domain Controllers, DnsAdmins

Requires read access to the domain partition and DNS application partitions.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER Zone
A specific DNS zone name to target. If omitted, all zones in the domain DNS
partition are evaluated.

.PARAMETER IncludeForestZones
When specified, also evaluates zones in the ForestDnsZones application partition.

.EXAMPLE
Find-DSADIDNSRecord -Domain 'contoso.com'

Returns DNS zone records writable by non-privileged principals in contoso.com.

.EXAMPLE
Find-DSADIDNSRecord -Zone 'contoso.com' -IncludeForestZones

Evaluates the specified zone and also checks the forest DNS partition.

.NOTES
#### Name:    Find-DSADIDNSRecord
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
        [string]$Zone,

        [Parameter()]
        [switch]$IncludeForestZones
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

        Write-Verbose "Querying domain: $DomainName for ADIDNS misconfiguration"

        $domainDn = 'DC=' + ($DomainName -replace '\.', ',DC=')

        # ── Rights that are dangerous on zone containers ──────────────────────

        $flaggedRights = @(
            [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
            [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
        )

        # ── Build privileged SID exclusion set ────────────────────────────────

        $excludedSids = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        [void]$excludedSids.Add('S-1-5-18')       # SYSTEM
        [void]$excludedSids.Add('S-1-5-32-544')   # Administrators
        [void]$excludedSids.Add('S-1-5-9')         # Enterprise Domain Controllers

        # Resolve domain-relative SIDs from domain root
        try
        {
            $domainRootEntry = [adsi]"LDAP://$DomainName"
            $domainSidBytes  = $domainRootEntry.objectSid.Value
            $domainSid       = (New-Object System.Security.Principal.SecurityIdentifier($domainSidBytes, 0)).ToString()
            $domainRootEntry.Dispose()

            [void]$excludedSids.Add("$domainSid-512")   # Domain Admins
            [void]$excludedSids.Add("$domainSid-516")   # Domain Controllers
            [void]$excludedSids.Add("$domainSid-519")   # Enterprise Admins
        }
        catch
        {
            Write-Verbose "Could not resolve domain SID for exclusion list: $_"
        }

        # Resolve DnsAdmins group SID (domain local group, RID varies)
        try
        {
            $dnsAdminsFilter  = '(&(objectClass=group)(sAMAccountName=DnsAdmins))'
            $dnsAdminsResults = Invoke-DSDirectorySearch -LdapPath "LDAP://$DomainName" `
                -Filter $dnsAdminsFilter -Properties @('objectSid')

            if ($dnsAdminsResults.Count -gt 0)
            {
                $dnsAdminsSidBytes = [byte[]]$dnsAdminsResults[0]['objectsid'][0]
                $dnsAdminsSid      = (New-Object System.Security.Principal.SecurityIdentifier($dnsAdminsSidBytes, 0)).ToString()
                [void]$excludedSids.Add($dnsAdminsSid)
                Write-Verbose "DnsAdmins SID resolved: $dnsAdminsSid"
            }
        }
        catch
        {
            Write-Verbose "Could not resolve DnsAdmins SID: $_"
        }

        # ── Build list of partitions to evaluate ──────────────────────────────

        $partitions = @(
            [PSCustomObject]@{
                Label    = 'Domain'
                RootPath = "LDAP://CN=MicrosoftDNS,DC=DomainDnsZones,$domainDn"
            }
        )

        if ($IncludeForestZones)
        {
            $partitions += [PSCustomObject]@{
                Label    = 'Forest'
                RootPath = "LDAP://CN=MicrosoftDNS,DC=ForestDnsZones,$domainDn"
            }
        }

        $zoneProperties = @('name', 'distinguishedName')
    }

    Process
    {
        foreach ($partition in $partitions)
        {
            Write-Verbose "Enumerating zones in partition: $($partition.Label) ($($partition.RootPath))"

            $zones = $null
            try
            {
                $zones = Invoke-DSDirectorySearch -LdapPath $partition.RootPath `
                    -Filter '(objectClass=dnsZone)' -Properties $zoneProperties
            }
            catch
            {
                Write-Verbose "Could not query DNS partition '$($partition.Label)': $_"
                continue
            }

            foreach ($zoneObj in $zones)
            {
                $zoneName = [string]$zoneObj['name'][0]
                $zoneDn   = [string]$zoneObj['distinguishedname'][0]

                # Apply -Zone filter if specified
                if ($Zone -and $zoneName -ne $Zone) { continue }

                Write-Verbose "Evaluating zone: $zoneName"

                # ── Pass 1: ACL check on the zone container ───────────────────

                $aces = Get-DSObjectAcl -LdapPath "LDAP://$zoneDn"

                foreach ($ace in $aces)
                {
                    if ($ace.AccessControlType -ne 'Allow') { continue }

                    # Check if this ACE grants any flagged right
                    $hasFlaggedRight = $false
                    $flaggedRightName = $null
                    foreach ($right in $flaggedRights)
                    {
                        if ($ace.ActiveDirectoryRights -band $right)
                        {
                            $hasFlaggedRight  = $true
                            $flaggedRightName = $right.ToString()
                            break
                        }
                    }
                    if (-not $hasFlaggedRight) { continue }

                    # Resolve identity to SID for exclusion check
                    $aceSid = $null
                    try
                    {
                        $ntAccount = New-Object System.Security.Principal.NTAccount($ace.IdentityReference)
                        $aceSid    = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).ToString()
                    }
                    catch { }

                    if ($aceSid -and $excludedSids.Contains($aceSid)) { continue }

                    [PSCustomObject]@{
                        ZoneName          = $zoneName
                        DistinguishedName = $zoneDn
                        FindingType       = 'UnexpectedWriteAccess'
                        Principal         = $ace.IdentityReference
                        Right             = $flaggedRightName
                        RecordName        = $null
                        Partition         = $partition.Label
                    }
                }

                # ── Pass 2: Wildcard dnsNode check ────────────────────────────
                # \2a is the LDAP escape for the '*' character

                $wildcardFilter  = '(&(objectClass=dnsNode)(name=\2a))'
                $wildcardResults = $null
                try
                {
                    $wildcardResults = Invoke-DSDirectorySearch `
                        -LdapPath "LDAP://$zoneDn" `
                        -Filter $wildcardFilter `
                        -Properties @('name', 'distinguishedName', 'dnsRecord')
                }
                catch
                {
                    Write-Verbose "Could not query wildcard record in zone '$zoneName': $_"
                }

                if ($null -ne $wildcardResults -and $wildcardResults.Count -gt 0)
                {
                    [PSCustomObject]@{
                        ZoneName          = $zoneName
                        DistinguishedName = $zoneDn
                        FindingType       = 'WildcardRecord'
                        Principal         = $null
                        Right             = $null
                        RecordName        = '*'
                        Partition         = $partition.Label
                    }
                }
            }
        }
    }

    End {}
}
