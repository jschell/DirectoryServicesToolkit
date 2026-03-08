function Find-DSInterestingACE
{
<#
.SYNOPSIS
Reads DACLs on AD objects and surfaces dangerous permissions granted to
non-privileged principals.

.DESCRIPTION
Enumerates Discretionary Access Control List (DACL) entries across Active
Directory objects and identifies ACEs that grant elevated rights to principals
that should not hold them. The following rights are flagged:

  GenericAll          — Full control; equivalent to domain admin over target
  GenericWrite        — Write to any non-protected attribute
  WriteDACL           — Modify the DACL; can grant any right
  WriteOwner          — Change object owner; owner can modify DACL
  AllExtendedRights   — Covers ForceChangePassword, GetChanges/GetChangesAll, etc.
  ForceChangePassword — Reset password without knowing current password

Requires read access to the domain partition. SACL reading requires
SeSecurityPrivilege; this function reads DACLs only.

Large domains may be slow. Use -SearchBase to scope to specific OUs.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER SearchBase
The distinguished name of the OU or container to limit the search to.
Without this, the entire domain partition is evaluated.

.PARAMETER TargetPrincipals
One or more SamAccountNames to check for dangerous rights. If omitted,
all non-default (non-admin) principals with elevated rights are returned.

.PARAMETER ExcludeAdmins
When specified, ACEs held by well-known admin groups (Domain Admins,
Enterprise Admins, SYSTEM, Administrators, Domain Controllers) are
filtered from output.

.PARAMETER IncludeInherited
When specified, inherited ACEs are included in results. By default only
explicit (non-inherited) ACEs are returned to reduce noise.

.PARAMETER SizeLimit
Maximum number of objects to evaluate. Defaults to 1000. Set to 0 for
unlimited — not recommended without a -SearchBase scope.

.EXAMPLE
Find-DSInterestingACE -Domain 'contoso.com' -ExcludeAdmins

Returns dangerous ACEs held by non-admin principals across the domain.

.EXAMPLE
Find-DSInterestingACE -SearchBase 'OU=ServiceAccounts,DC=contoso,DC=com' -TargetPrincipals 'helpdesk'

Checks whether the 'helpdesk' group holds dangerous rights over objects in
the ServiceAccounts OU.

.NOTES
#### Name:    Find-DSInterestingACE
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-03::0.1.0
- Initial creation
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param
    (
        [Parameter(HelpMessage = 'DNS name of the target domain')]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter(HelpMessage = 'DN of the OU or container to scope the search')]
        [string]$SearchBase,

        [Parameter(HelpMessage = 'SamAccountNames to check for dangerous rights')]
        [string[]]$TargetPrincipals,

        [Parameter(HelpMessage = 'Exclude well-known admin group ACEs from results')]
        [switch]$ExcludeAdmins,

        [Parameter(HelpMessage = 'Include inherited ACEs in results')]
        [switch]$IncludeInherited,

        [Parameter(HelpMessage = 'Maximum objects to evaluate (0 = unlimited)')]
        [ValidateRange(0, 100000)]
        [int]$SizeLimit = 1000
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

        Write-Verbose "Querying domain: $DomainName for interesting ACEs"

        # ── Rights to flag ───────────────────────────────────────────────────

        # Rights that are dangerous regardless of ObjectType restriction
        $script:FlaggedRights = @(
            [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
            [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner
            [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
        )

        # GenericAll (983551) — all standard AD rights combined
        $script:GenericAllValue = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll

        # ExtendedRight GUIDs
        $script:ForceChangePasswordGuid = [Guid]'00299570-246d-11d0-a768-00aa006e0529'

        # ── Admin SIDs to exclude (resolved at runtime) ──────────────────────

        $script:AdminSids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        if ($ExcludeAdmins)
        {
            # Well-known absolute SIDs
            [void]$script:AdminSids.Add('S-1-5-18')       # NT AUTHORITY\SYSTEM
            [void]$script:AdminSids.Add('S-1-5-32-544')   # BUILTIN\Administrators

            # Domain-relative SIDs — need domain SID first
            try
            {
                $domainRootEntry = [adsi]"LDAP://$DomainName"
                $domainSidBytes  = $domainRootEntry.objectSid.Value
                $domainSid       = New-Object System.Security.Principal.SecurityIdentifier($domainSidBytes, 0)
                $domainSidStr    = $domainSid.ToString()

                [void]$script:AdminSids.Add("$domainSidStr-512")   # Domain Admins
                [void]$script:AdminSids.Add("$domainSidStr-516")   # Domain Controllers
                [void]$script:AdminSids.Add("$domainSidStr-519")   # Enterprise Admins (may be in root domain)
                [void]$script:AdminSids.Add("$domainSidStr-520")   # Group Policy Creator Owners

                $domainRootEntry.Dispose()
                Write-Verbose "Admin SID exclusion list: $($script:AdminSids.Count) SIDs"
            }
            catch
            {
                Write-Verbose "Could not resolve domain SID for admin exclusion: $_"
            }
        }

        # ── Normalise TargetPrincipals to lowercase for comparison ───────────

        $script:TargetPrincipalSet = $null
        if ($TargetPrincipals -and $TargetPrincipals.Count -gt 0)
        {
            $script:TargetPrincipalSet = [System.Collections.Generic.HashSet[string]]::new(
                ($TargetPrincipals | ForEach-Object { $_.ToLower() }),
                [System.StringComparer]::OrdinalIgnoreCase
            )
        }

        # ── Search parameters ────────────────────────────────────────────────

        $ldapPath = if ($SearchBase)
        {
            "LDAP://$SearchBase"
        }
        else
        {
            "LDAP://$DomainName"
        }

        $ldapFilter = '(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit))'
        $properties = @('distinguishedName', 'sAMAccountName', 'objectClass')

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $objectList = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter `
            -Properties $properties -SizeLimit $SizeLimit

        Write-Verbose "Evaluating DACLs on $($objectList.Count) objects"

        foreach ($obj in $objectList)
        {
            $dn          = [string]$obj['distinguishedname'][0]
            $objectClass = ($obj['objectclass'] | Sort-Object -Descending)[0]  # most-specific class
            $objectLdap  = "LDAP://$dn"

            $aces = Get-DSObjectAcl -LdapPath $objectLdap

            foreach ($ace in $aces)
            {
                # Skip deny ACEs — focus on granted rights
                if ($ace.AccessControlType -ne 'Allow') { continue }

                # Skip inherited ACEs unless requested
                if ($ace.IsInherited -and -not $IncludeInherited) { continue }

                # Determine which flagged right(s) this ACE grants
                $flaggedRightName = Get-DSFlaggedRightName -AceRights $ace.ActiveDirectoryRights -AceObjectType $ace.ObjectType
                if (-not $flaggedRightName) { continue }

                # Resolve identity to SID for admin exclusion comparison
                $identityRef = $ace.IdentityReference
                if ($ExcludeAdmins)
                {
                    $aceSid = $null
                    try
                    {
                        $ntAccount = New-Object System.Security.Principal.NTAccount($identityRef)
                        $aceSid    = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).ToString()
                    }
                    catch
                    {
                        Write-Verbose "Could not resolve SID for '$identityRef': $_"
                    }

                    if ($aceSid -and $script:AdminSids.Contains($aceSid)) { continue }
                }

                # Filter to TargetPrincipals if specified
                if ($null -ne $script:TargetPrincipalSet)
                {
                    $principalShort = ($identityRef -split '\\')[-1]
                    if (-not $script:TargetPrincipalSet.Contains($principalShort)) { continue }
                }

                # RiskLevel: mapped from the specific right granted.
                # GenericAll / WriteDACL — full control or DACL rewrite; trivial path to domain compromise.
                # WriteOwner / GenericWrite / AllExtendedRights / ForceChangePassword — high-value
                # misconfigurations allowing targeted privilege escalation or credential reset.
                $aceRiskLevel = switch ($flaggedRightName)
                {
                    'GenericAll'          { 'Critical' }
                    'WriteDACL'           { 'Critical' }
                    'WriteOwner'          { 'High' }
                    'GenericWrite'        { 'High' }
                    'AllExtendedRights'   { 'High' }
                    'ForceChangePassword' { 'High' }
                    default               { 'Medium' }
                }

                [void]$results.Add(
                    [PSCustomObject]@{
                        TargetObject      = $dn
                        TargetObjectClass = $objectClass
                        Principal         = $identityRef
                        Right             = $flaggedRightName
                        AccessType        = $ace.AccessControlType
                        IsInherited       = $ace.IsInherited
                        RiskLevel         = $aceRiskLevel
                    }
                )
            }
        }
    }

    End
    {
        [PSCustomObject[]]$results
    }
}


function Get-DSFlaggedRightName
{
<#
.SYNOPSIS
Internal helper — maps an ActiveDirectoryRights value to a human-readable
dangerous right name, or returns $null if the right is not flagged.
#>

    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory)]
        [System.DirectoryServices.ActiveDirectoryRights]$AceRights,

        [Parameter()]
        [Guid]$AceObjectType = [Guid]::Empty
    )

    # GenericAll — full control (all 20 standard AD rights)
    if ($AceRights -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
    {
        return 'GenericAll'
    }

    # WriteDACL — can modify the DACL, effectively granting any right
    if ($AceRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)
    {
        return 'WriteDACL'
    }

    # WriteOwner — can change object owner, who can then modify DACL
    if ($AceRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)
    {
        return 'WriteOwner'
    }

    # GenericWrite — write any property
    if ($AceRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)
    {
        return 'GenericWrite'
    }

    # ExtendedRight — check for AllExtendedRights or specific dangerous GUIDs
    if ($AceRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)
    {
        if ($AceObjectType -eq [Guid]::Empty)
        {
            return 'AllExtendedRights'
        }
        elseif ($AceObjectType -eq [Guid]'00299570-246d-11d0-a768-00aa006e0529')
        {
            return 'ForceChangePassword'
        }
    }

    return $null
}
