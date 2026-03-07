function Find-DSWeakEncryptionAccounts
{
<#
.SYNOPSIS
Identifies user accounts configured with weak Kerberos encryption settings.

.DESCRIPTION
Queries user accounts with one or both of the following userAccountControl flags set:

  ENCRYPTED_TEXT_PASSWORD_ALLOWED (0x80 = 128)
    The account password is stored using reversible encryption — effectively plaintext.
    An attacker with access to the domain database (ntds.dit) or LSASS can recover the
    cleartext password directly without cracking.

  USE_DES_KEY_ONLY (0x200000 = 2097152)
    The account is restricted to DES Kerberos encryption types (DES-CBC-CRC, DES-CBC-MD5).
    DES is considered cryptographically broken and should not be used. This flag typically
    indicates a legacy application dependency that has not been remediated.

Both flags represent distinct but often overlapping remediation requirements. Accounts
holding privileged roles with either flag set are escalated to Critical risk.

Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeDisabled
When specified, includes disabled accounts in results. By default only enabled
accounts are returned, as disabled accounts cannot be immediately exploited.

.EXAMPLE
Find-DSWeakEncryptionAccounts -Domain 'contoso.com'

Returns all enabled accounts with reversible encryption or DES-only flags set.

.EXAMPLE
Find-DSWeakEncryptionAccounts -IncludeDisabled | Where-Object { $_.ReversibleEncryption }

Returns all accounts (including disabled) that store passwords with reversible encryption.

.EXAMPLE
Find-DSWeakEncryptionAccounts | Where-Object { $_.RiskLevel -eq 'Critical' }

Returns accounts with weak encryption flags that also hold privileged group membership.

.NOTES
#### Name:    Find-DSWeakEncryptionAccounts
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-07::0.1.0
- Initial creation — reversible encryption and DES-only UAC flag detection

#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
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
        try
        {
            $DomainName = Resolve-DSDomainName -Domain $Domain
        }
        catch
        {
            Write-Error "Cannot connect to domain '$Domain': $_"
            return
        }

        Write-Verbose "Querying domain: $DomainName for weak encryption account flags"

        $ldapPath = "LDAP://$DomainName"

        # UAC bit flags
        # ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x80  = 128
        # USE_DES_KEY_ONLY               = 0x200000 = 2097152
        # ACCOUNTDISABLE                 = 0x2    = 2

        # LDAP filter: users with reversible encryption OR DES-only flags
        # Using bitwise LDAP_MATCHING_RULE_BIT_AND (1.2.840.113556.1.4.803)
        $ldapFilter = if ($IncludeDisabled)
        {
            '(&(objectClass=user)(objectCategory=person)(|(userAccountControl:1.2.840.113556.1.4.803:=128)(userAccountControl:1.2.840.113556.1.4.803:=2097152)))'
        }
        else
        {
            '(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(userAccountControl:1.2.840.113556.1.4.803:=128)(userAccountControl:1.2.840.113556.1.4.803:=2097152)))'
        }

        $properties = @(
            'sAMAccountName'
            'distinguishedName'
            'userAccountControl'
            'pwdLastSet'
            'lastLogonTimestamp'
            'memberOf'
            'servicePrincipalName'
        )

        # Privileged group name patterns for risk escalation
        $privilegedPatterns = @(
            'Domain Admins'
            'Enterprise Admins'
            'Schema Admins'
            'Administrators'
            'Account Operators'
            'Backup Operators'
            'Server Operators'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $queryResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($obj in $queryResults)
        {
            $uac = [int]$obj['useraccountcontrol'][0]

            $reversibleEncryption = [bool]($uac -band 0x80)
            $desKeyOnly           = [bool]($uac -band 0x200000)
            $isEnabled            = -not [bool]($uac -band 0x2)

            $memberOf = if ($null -ne $obj['memberof'])
            {
                @($obj['memberof'] | ForEach-Object { [string]$_ })
            }
            else
            {
                @()
            }

            $spns = if ($null -ne $obj['serviceprincipalname'])
            {
                @($obj['serviceprincipalname'] | ForEach-Object { [string]$_ })
            }
            else
            {
                @()
            }

            $pwdLastSetRaw = $obj['pwdlastset'][0]
            $passwordLastSet = if ($null -ne $pwdLastSetRaw -and [long]$pwdLastSetRaw -gt 0)
            {
                [DateTime]::FromFileTime([long]$pwdLastSetRaw)
            }
            else
            {
                $null
            }

            $lastLogonRaw = $obj['lastlogontimestamp'][0]
            $lastLogon = if ($null -ne $lastLogonRaw -and [long]$lastLogonRaw -gt 0)
            {
                [DateTime]::FromFileTime([long]$lastLogonRaw)
            }
            else
            {
                $null
            }

            # Check for privileged group membership in the memberOf list
            $isPrivileged = $false
            foreach ($group in $memberOf)
            {
                foreach ($pattern in $privilegedPatterns)
                {
                    if ($group -match [regex]::Escape($pattern))
                    {
                        $isPrivileged = $true
                        break
                    }
                }
                if ($isPrivileged) { break }
            }

            $weakFlags = @()
            if ($reversibleEncryption) { $weakFlags += 'ReversibleEncryption' }
            if ($desKeyOnly)           { $weakFlags += 'DESKeyOnly' }

            $riskLevel = if ($isPrivileged)
            {
                'Critical'
            }
            elseif ($reversibleEncryption)
            {
                'High'
            }
            else
            {
                'Medium'
            }

            $findingParts = @()
            if ($reversibleEncryption) { $findingParts += 'password stored with reversible encryption (plaintext-equivalent)' }
            if ($desKeyOnly)           { $findingParts += 'account restricted to DES Kerberos encryption (cryptographically broken)' }
            $findingText = $findingParts -join '; '
            if ($isPrivileged) { $findingText = "[Privileged Account] $findingText" }

            [void]$results.Add(
                [PSCustomObject]@{
                    SamAccountName        = [string]$obj['samaccountname'][0]
                    DistinguishedName     = [string]$obj['distinguishedname'][0]
                    Enabled               = $isEnabled
                    ReversibleEncryption  = $reversibleEncryption
                    DESKeyOnly            = $desKeyOnly
                    WeakFlags             = $weakFlags
                    PasswordLastSet       = $passwordLastSet
                    LastLogon             = $lastLogon
                    HasSPN                = ($spns.Count -gt 0)
                    IsPrivileged          = $isPrivileged
                    RiskLevel             = $riskLevel
                    Finding               = $findingText
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property RiskLevel, SamAccountName
    }
}
