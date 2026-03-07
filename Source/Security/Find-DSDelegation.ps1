function Find-DSDelegation
{
<#
.SYNOPSIS
Enumerates Active Directory objects configured with Kerberos delegation.

.DESCRIPTION
Finds all three forms of Kerberos delegation configured in Active Directory:

  Unconstrained — Accounts/computers where TrustedForDelegation is set.
    Any service authenticating to these systems hands over a full TGT,
    enabling credential harvesting. Critical severity.

  Constrained — Accounts with msDS-AllowedToDelegateTo populated.
    Covers both standard constrained delegation and protocol transition
    (TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION).

  RBCD — Computer objects where msDS-AllowedToActOnBehalfOfOtherIdentity
    is set. Resource-based constrained delegation; exploitable when
    an attacker controls an account with an SPN.

Requires read access to the domain partition. No special privileges needed
for enumeration.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER DelegationType
The delegation type to enumerate: Unconstrained, Constrained, RBCD, or All.
Defaults to All.

.PARAMETER ExcludeComputerAccounts
When specified, computer accounts are excluded from results. Useful for
focusing on user and service accounts only.

.EXAMPLE
Find-DSDelegation -Domain 'contoso.com'

Returns all delegation configurations across the domain.

.EXAMPLE
Find-DSDelegation -Domain 'contoso.com' -DelegationType Unconstrained

Returns only accounts with unconstrained delegation configured.

.EXAMPLE
Find-DSDelegation -DelegationType Constrained -ExcludeComputerAccounts

Returns constrained delegation configurations, excluding computer accounts.

.NOTES
#### Name:    Find-DSDelegation
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

        [Parameter(HelpMessage = 'Delegation type to enumerate')]
        [ValidateSet('Unconstrained', 'Constrained', 'RBCD', 'All')]
        [string]$DelegationType = 'All',

        [Parameter(HelpMessage = 'Exclude computer accounts from results')]
        [switch]$ExcludeComputerAccounts
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

        Write-Verbose "Querying domain: $DomainName for delegation type: $DelegationType"

        $ldapPath   = "LDAP://$DomainName"
        $properties = @(
            'distinguishedName'
            'sAMAccountName'
            'userAccountControl'
            'msDS-AllowedToDelegateTo'
            'msDS-AllowedToActOnBehalfOfOtherIdentity'
            'objectClass'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        # ── Unconstrained delegation ─────────────────────────────────────────

        if ($DelegationType -eq 'All' -or $DelegationType -eq 'Unconstrained')
        {
            # Users with unconstrained delegation
            $userFilter = '(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(cn=krbtgt)))'
            Write-Verbose "Querying unconstrained delegation (users): $userFilter"

            $userResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $userFilter -Properties $properties

            foreach ($obj in $userResults)
            {
                $uac = [int]$obj['useraccountcontrol'][0]
                # RiskLevel: Unconstrained delegation causes the KDC to embed a full TGT in
                # service tickets — any service on these hosts can harvest credentials for any
                # authenticating account. This is universally Critical.
                [void]$results.Add(
                    [PSCustomObject]@{
                        SamAccountName     = [string]$obj['samaccountname'][0]
                        DistinguishedName  = [string]$obj['distinguishedname'][0]
                        DelegationType     = 'Unconstrained'
                        ProtocolTransition = [bool]($uac -band 16777216)
                        DelegationTarget   = $null
                        RBCDTarget         = $null
                        Enabled            = -not [bool]($uac -band 2)
                        ObjectType         = 'User'
                        RiskLevel          = 'Critical'
                    }
                )
            }

            # Computers with unconstrained delegation (skip if -ExcludeComputerAccounts)
            if (-not $ExcludeComputerAccounts)
            {
                $compFilter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
                Write-Verbose "Querying unconstrained delegation (computers): $compFilter"

                $compResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $compFilter -Properties $properties

                foreach ($obj in $compResults)
                {
                    $uac = [int]$obj['useraccountcontrol'][0]
                    [void]$results.Add(
                        [PSCustomObject]@{
                            SamAccountName     = [string]$obj['samaccountname'][0]
                            DistinguishedName  = [string]$obj['distinguishedname'][0]
                            DelegationType     = 'Unconstrained'
                            ProtocolTransition = [bool]($uac -band 16777216)
                            DelegationTarget   = $null
                            RBCDTarget         = $null
                            Enabled            = -not [bool]($uac -band 2)
                            ObjectType         = 'Computer'
                            RiskLevel          = 'Critical'
                        }
                    )
                }
            }
        }

        # ── Constrained delegation ───────────────────────────────────────────

        if ($DelegationType -eq 'All' -or $DelegationType -eq 'Constrained')
        {
            $constrainedFilter = if ($ExcludeComputerAccounts)
            {
                '(&(objectClass=user)(msDS-AllowedToDelegateTo=*)(!(cn=krbtgt))(!(objectCategory=computer)))'
            }
            else
            {
                '(&(objectClass=user)(msDS-AllowedToDelegateTo=*)(!(cn=krbtgt)))'
            }

            Write-Verbose "Querying constrained delegation: $constrainedFilter"

            $constrainedResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $constrainedFilter -Properties $properties

            foreach ($obj in $constrainedResults)
            {
                $uac        = [int]$obj['useraccountcontrol'][0]
                $targets    = @($obj['msds-allowedtodelegateto'])
                $objectType = if ($obj['objectclass'] -contains 'computer') { 'Computer' } else { 'User' }

                # RiskLevel: Protocol transition (TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) lets the
                # service impersonate any user to any service in the delegate-to list without
                # requiring a forwarded TGT — elevation to High. Standard constrained delegation
                # requires a user TGS, narrowing the scope — Medium.
                $constrainedRisk = if ([bool]($uac -band 16777216)) { 'High' } else { 'Medium' }

                [void]$results.Add(
                    [PSCustomObject]@{
                        SamAccountName     = [string]$obj['samaccountname'][0]
                        DistinguishedName  = [string]$obj['distinguishedname'][0]
                        DelegationType     = 'Constrained'
                        ProtocolTransition = [bool]($uac -band 16777216)
                        DelegationTarget   = $targets
                        RBCDTarget         = $null
                        Enabled            = -not [bool]($uac -band 2)
                        ObjectType         = $objectType
                        RiskLevel          = $constrainedRisk
                    }
                )
            }
        }

        # ── Resource-based constrained delegation (RBCD) ────────────────────

        if (($DelegationType -eq 'All' -or $DelegationType -eq 'RBCD') -and -not $ExcludeComputerAccounts)
        {
            $rbcdFilter = '(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))'
            Write-Verbose "Querying RBCD: $rbcdFilter"

            $rbcdResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $rbcdFilter -Properties $properties

            foreach ($obj in $rbcdResults)
            {
                $uac       = [int]$obj['useraccountcontrol'][0]
                $rbcdBytes = $obj['msds-allowedtoactonbehalfofotheridentity'][0]
                $rbcdSddl  = $null

                if ($null -ne $rbcdBytes)
                {
                    try
                    {
                        $sd       = [System.Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$rbcdBytes, 0)
                        $rbcdSddl = $sd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
                    }
                    catch
                    {
                        Write-Verbose "Could not parse RBCD descriptor for $($obj['samaccountname'][0]): $_"
                    }
                }

                # RiskLevel: RBCD requires an attacker to already control an account with an SPN
                # (e.g. via MachineAccountQuota) and write access to the target computer's
                # msDS-AllowedToActOnBehalfOfOtherIdentity. Elevated risk but requires prior access.
                [void]$results.Add(
                    [PSCustomObject]@{
                        SamAccountName     = [string]$obj['samaccountname'][0]
                        DistinguishedName  = [string]$obj['distinguishedname'][0]
                        DelegationType     = 'RBCD'
                        ProtocolTransition = $false
                        DelegationTarget   = $null
                        RBCDTarget         = $rbcdSddl
                        Enabled            = -not [bool]($uac -band 2)
                        ObjectType         = 'Computer'
                        RiskLevel          = 'Medium'
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
