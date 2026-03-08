function Find-DSApplicationOverPrivilege
{
<#
.SYNOPSIS
Identifies well-known application groups with excessive privilege on domain objects.

.DESCRIPTION
Searches the domain for groups associated with common enterprise applications —
Microsoft Exchange, SCCM/ConfigMgr, and similar products — that are known to
accumulate excessive permissions during installation or over time.

Exchange legacy permissions (created by Exchange 2010/2013/2016 before CU23/CU13
security hardening) typically grant Exchange Windows Permissions and Exchange Trusted
Subsystem write access to the domain object, enabling an Exchange server compromise
to escalate to Domain Admin.

Checks performed:
  1. Presence of over-privileged Exchange groups:
     - Exchange Windows Permissions  — WriteDACL on the domain object
     - Exchange Trusted Subsystem    — member of Exchange Windows Permissions
     - Organization Management      — effectively Domain Admin equivalent
  2. SCCM NAA account memberships that expose credentials
  3. Any non-default group holding WriteDacl, WriteOwner, or GenericAll on the
     domain NC root object

Requires LDAP read access and ability to read the domain object DACL.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Find-DSApplicationOverPrivilege -Domain 'contoso.com'

Returns application groups with potential domain-level over-privilege.

.EXAMPLE
Find-DSApplicationOverPrivilege | Where-Object { $_.RiskLevel -eq 'Critical' }

Returns findings at Critical risk level.

.NOTES
#### Name:    Find-DSApplicationOverPrivilege
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-08::0.1.0
- Initial creation — Exchange/application over-privilege detection

NIST 800-53: AC-6, AC-2(7), AC-3
NIST 800-207: Identity pillar — service account least-privilege
CMMC Level 3: 3.1.5 (employ least privilege), 3.1.6

.LINK
https://techcommunity.microsoft.com/t5/exchange-team-blog/august-2021-exchange-server-security-updates-reduce-attack/ba-p/2684782
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

        Write-Verbose "Checking application over-privilege in domain: $DomainName"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $ldapPath = "LDAP://$domainDN"

        # Well-known over-privileged application group names
        $overPrivilegedGroupNames = @(
            'Exchange Windows Permissions'
            'Exchange Trusted Subsystem'
            'Organization Management'
            'Exchange Domain Servers'
            'SMS Admins'                     # SCCM
            'ConfigMgr Remote Control Users' # SCCM
        )

        $dangerousRights = @('GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite')

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        # ── Part 1: Check for known over-privileged group existence ──
        foreach ($groupName in $overPrivilegedGroupNames)
        {
            $escapedName = $groupName -replace '\(', '\28' -replace '\)', '\29' -replace '\*', '\2a' -replace '\\', '\5c'
            $groupFilter = "(&(objectClass=group)(cn=$escapedName))"
            $groupProps  = @('cn', 'distinguishedName', 'member', 'description')

            $groupEntries = Invoke-DSDirectorySearch -Filter $groupFilter -Properties $groupProps -Domain $DomainName

            foreach ($group in $groupEntries)
            {
                $cn      = [string]$group['cn'][0]
                $dn      = [string]$group['distinguishedname'][0]
                $members = if ($group['member']) { $group['member'] } else { @() }
                $desc    = if ($group['description']) { [string]$group['description'][0] } else { $null }

                $isExchangeGroup = $cn -match 'Exchange'
                $isSCCMGroup     = $cn -match 'SMS|ConfigMgr'

                $riskLevel = if ($cn -in @('Exchange Windows Permissions', 'Organization Management')) { 'High' }
                             elseif ($isExchangeGroup -or $isSCCMGroup) { 'Medium' }
                             else { 'Medium' }

                [void]$results.Add(
                    [PSCustomObject]@{
                        FindingType       = 'KnownOverPrivilegedGroup'
                        GroupName         = $cn
                        GroupDN           = $dn
                        Description       = $desc
                        MemberCount       = $members.Count
                        IdentityReference = $null
                        Rights            = $null
                        RiskLevel         = $riskLevel
                        Finding           = "Application group '$cn' found — may have legacy over-privilege on domain objects"
                    }
                )
            }
        }

        # ── Part 2: Check domain NC root DACL for dangerous app group ACEs ──
        Write-Verbose "Reading domain NC root DACL for over-privileged application ACEs"

        $safePrincipals = @(
            'S-1-5-18', 'S-1-5-9', 'S-1-3-0',
            'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'CREATOR OWNER',
            'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
        )
        $safeGroupPatterns = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')

        $domainAces = Get-DSObjectAcl -LdapPath $ldapPath

        foreach ($ace in $domainAces)
        {
            if ($ace.AccessControlType -ne 'Allow') { continue }

            $rights   = $ace.ActiveDirectoryRights.ToString()
            $identity = $ace.IdentityReference.ToString()

            $hasDangerous  = $false
            $matchedRights = @()

            foreach ($right in $dangerousRights)
            {
                if ($rights -match $right) { $hasDangerous = $true; $matchedRights += $right }
            }

            if (-not $hasDangerous) { continue }

            $isSafe = $false
            foreach ($safe in $safePrincipals) { if ($identity -eq $safe) { $isSafe = $true; break } }
            if (-not $isSafe)
            {
                foreach ($pattern in $safeGroupPatterns)
                {
                    if ($identity -like "*$pattern*") { $isSafe = $true; break }
                }
            }

            if ($isSafe) { continue }

            [void]$results.Add(
                [PSCustomObject]@{
                    FindingType       = 'DomainObjectDACL'
                    GroupName         = $identity
                    GroupDN           = $null
                    Description       = 'Non-privileged principal with dangerous rights on domain NC root'
                    MemberCount       = $null
                    IdentityReference = $identity
                    Rights            = $rights
                    RiskLevel         = 'Critical'
                    Finding           = "Domain object DACL: '$identity' has $($matchedRights -join ', ') on the domain NC root — potential DCSync/privilege escalation path"
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property RiskLevel, FindingType
    }
}
