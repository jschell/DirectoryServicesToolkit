function Find-DSPasswordNeverExpires
{
<#
.SYNOPSIS
Finds accounts with the DONT_EXPIRE_PASSWORD flag set in userAccountControl.

.DESCRIPTION
Identifies user accounts with the DONT_EXPIRE_PASSWORD flag (userAccountControl
bit 0x10000 / 65536) set. Passwords that never expire accumulate age over time,
increasing the window for offline attacks on captured hashes.

Cross-referencing output with Find-DSKerberoastable results surfaces the
highest-risk overlap — service accounts with SPNs that also have non-expiring
passwords. Use 'Where-Object HasSPN' to filter to this subset.

Results are sorted by PasswordAgeDays descending (oldest password first).

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeDisabled
When specified, disabled accounts with DONT_EXPIRE_PASSWORD are included.

.EXAMPLE
Find-DSPasswordNeverExpires -Domain 'contoso.com'

Returns all enabled accounts with non-expiring passwords.

.EXAMPLE
Find-DSPasswordNeverExpires -IncludeDisabled

Returns all accounts (enabled and disabled) with non-expiring passwords.

.NOTES
#### Name:    Find-DSPasswordNeverExpires
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
        try
        {
            $DomainName = Resolve-DSDomainName -Domain $Domain
        }
        catch
        {
            Write-Error "Cannot connect to domain '$Domain': $_"
            return
        }

        Write-Verbose "Querying domain: $DomainName for DONT_EXPIRE_PASSWORD accounts"

        # UAC bit 65536 (0x10000) = DONT_EXPIRE_PASSWORD
        $filterParts = @(
            '(objectClass=user)'
            '(userAccountControl:1.2.840.113556.1.4.803:=65536)'
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
            'servicePrincipalName'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $queryResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        $now = Get-Date

        foreach ($obj in $queryResults)
        {
            $uac = [int]$obj['useraccountcontrol'][0]

            $pwdLastSetRaw = $obj['pwdlastset'][0]
            if ($null -ne $pwdLastSetRaw -and [long]$pwdLastSetRaw -gt 0)
            {
                $passwordLastSet = [DateTime]::FromFileTime([long]$pwdLastSetRaw)
                $passwordAgeDays = [int]($now - $passwordLastSet).TotalDays
            }
            else
            {
                $passwordLastSet = $null
                $passwordAgeDays = $null
            }

            $spnRaw = $obj['serviceprincipalname']
            $hasSPN = ($null -ne $spnRaw -and $spnRaw.Count -gt 0 -and $null -ne $spnRaw[0])
            $spns   = if ($hasSPN) { @($spnRaw) } else { @() }

            [void]$results.Add(
                [PSCustomObject]@{
                    SamAccountName    = [string]$obj['samaccountname'][0]
                    DistinguishedName = [string]$obj['distinguishedname'][0]
                    Enabled           = -not [bool]($uac -band 2)
                    PasswordLastSet   = $passwordLastSet
                    PasswordAgeDays   = $passwordAgeDays
                    HasSPN            = $hasSPN
                    SPNs              = $spns
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property PasswordAgeDays -Descending
    }
}
