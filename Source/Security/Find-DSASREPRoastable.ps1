function Find-DSASREPRoastable
{
<#
.SYNOPSIS
Finds accounts with the DONT_REQUIRE_PREAUTH flag set in userAccountControl.

.DESCRIPTION
Enumerates user accounts in Active Directory where Kerberos pre-authentication
is disabled (userAccountControl flag 0x400000 / 4194304). These accounts can
be attacked without credentials — an unauthenticated attacker can request an
AS-REP for each account and attempt to crack the response offline (AS-REP
Roasting).

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeDisabled
When specified, disabled accounts with DONT_REQUIRE_PREAUTH are included.
Useful for complete assessment coverage even when immediate risk is lower.

.EXAMPLE
Find-DSASREPRoastable -Domain 'contoso.com'

Returns all enabled accounts with Kerberos pre-authentication disabled.

.EXAMPLE
Find-DSASREPRoastable -IncludeDisabled

Returns all accounts (enabled and disabled) with pre-authentication disabled.

.NOTES
#### Name:    Find-DSASREPRoastable
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

        [Parameter(HelpMessage = 'Include disabled accounts in results')]
        [switch]$IncludeDisabled
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

        Write-Verbose "Querying domain: $DomainName for AS-REP roastable accounts"

        # UAC bit 4194304 (0x400000) = DONT_REQUIRE_PREAUTH
        $filterParts = @(
            '(objectClass=user)'
            '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
        )

        if (-not $IncludeDisabled)
        {
            $filterParts += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
        }

        $ldapFilter = '(&{0})' -f ($filterParts -join '')
        Write-Verbose "LDAP filter: $ldapFilter"

        $ldapPath   = "LDAP://$DomainName"
        $properties = @(
            'distinguishedName'
            'sAMAccountName'
            'userAccountControl'
            'memberOf'
            'pwdLastSet'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $queryResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($obj in $queryResults)
        {
            $uac = [int]$obj['useraccountcontrol'][0]

            $pwdLastSetRaw = $obj['pwdlastset'][0]
            $passwordLastSet = if ($null -ne $pwdLastSetRaw -and [long]$pwdLastSetRaw -gt 0)
            {
                [DateTime]::FromFileTime([long]$pwdLastSetRaw)
            }
            else
            {
                $null
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    SamAccountName    = [string]$obj['samaccountname'][0]
                    DistinguishedName = [string]$obj['distinguishedname'][0]
                    Enabled           = -not [bool]($uac -band 2)
                    PasswordLastSet   = $passwordLastSet
                    MemberOf          = @($obj['memberof'])
                }
            )
        }
    }

    End
    {
        [PSCustomObject[]]$results
    }
}
