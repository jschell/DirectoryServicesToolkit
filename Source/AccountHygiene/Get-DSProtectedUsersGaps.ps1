function Get-DSProtectedUsersGaps
{
<#
.SYNOPSIS
Identifies privileged accounts not in the Protected Users group.

.DESCRIPTION
Enumerates members of high-privilege groups (Domain Admins, Enterprise Admins, Schema
Admins, Administrators, Account Operators, Backup Operators) and compares against the
Protected Users group membership. Privileged accounts outside Protected Users retain
unnecessary attack surface: they can use NTLM, DES/RC4 Kerberos, and unconstrained
delegation, all of which are restricted for Protected Users members.

Also flags incompatible configurations for accounts that are in Protected Users:
- Accounts with SPNs set (Kerberos service tickets will fail for Protected Users members)
- Accounts with unconstrained delegation (incompatible with Protected Users)

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Get-DSProtectedUsersGaps -Domain 'contoso.com'

Returns privileged accounts missing from Protected Users in contoso.com.

.EXAMPLE
Get-DSProtectedUsersGaps -Domain 'contoso.com' | Where-Object { -not $_.InProtectedUsers }

Returns only privileged accounts that are NOT in the Protected Users group.

.NOTES
#### Name:    Get-DSProtectedUsersGaps
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

        Write-Verbose "Checking Protected Users gaps in domain: $DomainName"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $ldapPath = "LDAP://$domainDN"

        $privilegedGroupNames = @(
            'Domain Admins'
            'Enterprise Admins'
            'Schema Admins'
            'Administrators'
            'Account Operators'
            'Backup Operators'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        # Fetch Protected Users members
        $puFilter     = '(&(objectClass=group)(cn=Protected Users))'
        $puProperties = @('member')
        $puResult     = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $puFilter -Properties $puProperties

        $protectedUsersDNs = New-Object System.Collections.Generic.HashSet[string]

        if ($null -ne $puResult -and $puResult.Count -gt 0)
        {
            $memberList = $puResult[0]['member']
            if ($null -ne $memberList)
            {
                foreach ($memberDN in $memberList)
                {
                    [void]$protectedUsersDNs.Add(([string]$memberDN).ToLowerInvariant())
                }
            }
        }

        Write-Verbose "Protected Users group has $($protectedUsersDNs.Count) direct member(s)"

        # Process each privileged group
        foreach ($groupName in $privilegedGroupNames)
        {
            $escapedName  = $groupName -replace '\(', '\28' -replace '\)', '\29'
            $groupFilter  = "(&(objectClass=group)(cn=$escapedName))"
            $groupProps   = @('member')
            $groupResult  = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $groupFilter -Properties $groupProps

            if ($null -eq $groupResult -or $groupResult.Count -eq 0) { continue }

            $memberDNs = $groupResult[0]['member']
            if ($null -eq $memberDNs) { continue }

            foreach ($memberDN in $memberDNs)
            {
                $memberDNStr = [string]$memberDN

                # Fetch user attributes
                $userFilter = "(distinguishedName=$memberDNStr)"
                $userProps  = @('name', 'sAMAccountName', 'distinguishedName', 'userAccountControl', 'servicePrincipalName')
                $userResult = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $userFilter -Properties $userProps

                if ($null -eq $userResult -or $userResult.Count -eq 0) { continue }

                $user = $userResult[0]

                $uac  = if ($null -ne $user['useraccountcontrol'] -and $user['useraccountcontrol'].Count -gt 0) { [int]$user['useraccountcontrol'][0] } else { 0 }
                $spns = if ($null -ne $user['serviceprincipalname'] -and $user['serviceprincipalname'].Count -gt 0) { @($user['serviceprincipalname']) } else { @() }

                $inProtectedUsers     = $protectedUsersDNs.Contains($memberDNStr.ToLowerInvariant())
                $hasUnconstrained     = [bool]($uac -band 0x80000)  # TRUSTED_FOR_DELEGATION
                $hasSPN               = ($spns.Count -gt 0)
                $isEnabled            = -not [bool]($uac -band 0x2)

                # Incompatibility flags for accounts IN Protected Users
                $incompatSPN          = $inProtectedUsers -and $hasSPN
                $incompatDelegation   = $inProtectedUsers -and $hasUnconstrained

                [void]$results.Add(
                    [PSCustomObject]@{
                        SamAccountName       = [string]$user['samaccountname'][0]
                        DistinguishedName    = $memberDNStr
                        Enabled              = $isEnabled
                        PrivilegedGroup       = $groupName
                        InProtectedUsers     = $inProtectedUsers
                        HasSPN               = $hasSPN
                        HasUnconstrainedDelegation = $hasUnconstrained
                        IncompatibleSPN      = $incompatSPN
                        IncompatibleDelegation = $incompatDelegation
                        RiskLevel            = if (-not $inProtectedUsers -and $isEnabled) { 'High' } elseif ($incompatSPN -or $incompatDelegation) { 'Medium' } else { 'Low' }
                        Finding              = if (-not $inProtectedUsers -and $isEnabled) { "Privileged account '$([string]$user['samaccountname'][0])' ($groupName) is not in Protected Users" }
                                               elseif ($incompatSPN) { "Account '$([string]$user['samaccountname'][0])' is in Protected Users but has SPNs set — Kerberos service tickets will fail" }
                                               elseif ($incompatDelegation) { "Account '$([string]$user['samaccountname'][0])' is in Protected Users but has unconstrained delegation — delegation will not function" }
                                               else { $null }
                    }
                )
            }
        }
    }

    End
    {
        # Deduplicate by SamAccountName + Group (same user may be in multiple groups)
        $unique = $results | Sort-Object -Property SamAccountName, PrivilegedGroup -Unique
        $unique | Sort-Object -Property RiskLevel, SamAccountName
    }
}
