function Find-DSPasswordNotRequired
{
<#
.SYNOPSIS
Finds accounts where the PASSWD_NOTREQD flag is set in userAccountControl.

.DESCRIPTION
Identifies user accounts with the PASSWD_NOTREQD flag (userAccountControl bit
0x20 / 32) set. When this flag is present, the account can authenticate with
an empty password if no domain password policy enforces a minimum length for
that account (e.g. if a Fine-Grained Password Policy does not apply).

These accounts represent a potential blank-password authentication risk and
should be reviewed. This flag is sometimes set during bulk account creation
and never cleared.

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeDisabled
When specified, disabled accounts with PASSWD_NOTREQD are included in results.

.EXAMPLE
Find-DSPasswordNotRequired -Domain 'contoso.com'

Returns all enabled accounts with PASSWD_NOTREQD set.

.EXAMPLE
Find-DSPasswordNotRequired -IncludeDisabled

Returns all accounts (enabled and disabled) with PASSWD_NOTREQD set.

.NOTES
#### Name:    Find-DSPasswordNotRequired
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

        Write-Verbose "Querying domain: $DomainName for PASSWD_NOTREQD accounts"

        # UAC bit 32 (0x20) = PASSWD_NOTREQD
        $filterParts = @(
            '(objectClass=user)'
            '(userAccountControl:1.2.840.113556.1.4.803:=32)'
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
            'pwdLastSet'
            'memberOf'
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
                    PasswordNeverSet  = ($null -eq $passwordLastSet)
                }
            )
        }
    }

    End
    {
        if ($results.Count -gt 10)
        {
            Write-Warning "$($results.Count) accounts found with PASSWD_NOTREQD set — this may indicate a bulk provisioning hygiene issue."
        }

        $results
    }
}
