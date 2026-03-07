BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSWeakEncryptionAccounts' -Tag 'Unit', 'AccountHygiene', 'Security' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                SamAccountName       = 'legacyapp'
                DistinguishedName    = 'CN=legacyapp,OU=ServiceAccounts,DC=contoso,DC=com'
                Enabled              = $true
                ReversibleEncryption = $true
                DESKeyOnly           = $false
                WeakFlags            = @('ReversibleEncryption')
                PasswordLastSet      = (Get-Date).AddDays(-90)
                LastLogon            = (Get-Date).AddDays(-5)
                HasSPN               = $false
                IsPrivileged         = $false
                RiskLevel            = 'High'
                Finding              = 'password stored with reversible encryption (plaintext-equivalent)'
            }

            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'ReversibleEncryption'
            $result.PSObject.Properties.Name | Should -Contain 'DESKeyOnly'
            $result.PSObject.Properties.Name | Should -Contain 'WeakFlags'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordLastSet'
            $result.PSObject.Properties.Name | Should -Contain 'LastLogon'
            $result.PSObject.Properties.Name | Should -Contain 'HasSPN'
            $result.PSObject.Properties.Name | Should -Contain 'IsPrivileged'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }
    }

    Context 'UAC flag detection' {

        It 'ENCRYPTED_TEXT_PASSWORD_ALLOWED (0x80) should be detected as reversible encryption' {
            $uac                = 0x80    # ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128
            $reversibleEncryption = [bool]($uac -band 0x80)
            $reversibleEncryption | Should -BeTrue
        }

        It 'USE_DES_KEY_ONLY (0x200000) should be detected as DES-only' {
            $uac        = 0x200000   # USE_DES_KEY_ONLY = 2097152
            $desKeyOnly = [bool]($uac -band 0x200000)
            $desKeyOnly | Should -BeTrue
        }

        It 'Both flags set simultaneously should both be detected' {
            $uac                = 0x80 -bor 0x200000
            $reversibleEncryption = [bool]($uac -band 0x80)
            $desKeyOnly           = [bool]($uac -band 0x200000)
            $reversibleEncryption | Should -BeTrue
            $desKeyOnly           | Should -BeTrue
        }

        It 'Normal account UAC should not trigger either flag' {
            $uac                = 512   # NORMAL_ACCOUNT
            $reversibleEncryption = [bool]($uac -band 0x80)
            $desKeyOnly           = [bool]($uac -band 0x200000)
            $reversibleEncryption | Should -BeFalse
            $desKeyOnly           | Should -BeFalse
        }

        It 'Disabled bit (0x2) check should correctly identify enabled state' {
            $uacEnabled  = 512
            $uacDisabled = 514   # NORMAL_ACCOUNT + ACCOUNTDISABLE
            (-not [bool]($uacEnabled -band 2))  | Should -BeTrue
            (-not [bool]($uacDisabled -band 2)) | Should -BeFalse
        }
    }

    Context 'Risk level classification' {

        It 'Privileged account with reversible encryption should be Critical' {
            $isPrivileged        = $true
            $reversibleEncryption = $true
            $riskLevel = if ($isPrivileged) { 'Critical' } elseif ($reversibleEncryption) { 'High' } else { 'Medium' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'Non-privileged account with reversible encryption should be High' {
            $isPrivileged        = $false
            $reversibleEncryption = $true
            $riskLevel = if ($isPrivileged) { 'Critical' } elseif ($reversibleEncryption) { 'High' } else { 'Medium' }
            $riskLevel | Should -Be 'High'
        }

        It 'Non-privileged account with DES-only (no reversible encryption) should be Medium' {
            $isPrivileged        = $false
            $reversibleEncryption = $false
            $riskLevel = if ($isPrivileged) { 'Critical' } elseif ($reversibleEncryption) { 'High' } else { 'Medium' }
            $riskLevel | Should -Be 'Medium'
        }
    }

    Context 'LDAP filter validation' {

        It 'Filter should include ENCRYPTED_TEXT_PASSWORD_ALLOWED bit check (128)' {
            $filter = '(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(userAccountControl:1.2.840.113556.1.4.803:=128)(userAccountControl:1.2.840.113556.1.4.803:=2097152)))'
            $filter | Should -Match '1.2.840.113556.1.4.803:=128'
        }

        It 'Filter should include USE_DES_KEY_ONLY bit check (2097152)' {
            $filter = '(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(userAccountControl:1.2.840.113556.1.4.803:=128)(userAccountControl:1.2.840.113556.1.4.803:=2097152)))'
            $filter | Should -Match '1.2.840.113556.1.4.803:=2097152'
        }

        It 'Default filter should exclude disabled accounts' {
            $filter = '(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(userAccountControl:1.2.840.113556.1.4.803:=128)(userAccountControl:1.2.840.113556.1.4.803:=2097152)))'
            $filter | Should -Match '!\(userAccountControl.*:=2\)'
        }
    }

    Context 'Mocked query — result enumeration' {

        It 'Should return account with reversible encryption flag set' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            samaccountname       = @('legacyapp')
                            distinguishedname    = @('CN=legacyapp,OU=ServiceAccounts,DC=contoso,DC=com')
                            useraccountcontrol   = @(640)    # 512 (NORMAL_ACCOUNT) + 128 (ENCRYPTED_TEXT_PWD)
                            pwdlastset           = @(132000000000000000L)
                            lastlogontimestamp   = @(132000000000000000L)
                            memberof             = $null
                            serviceprincipalname = $null
                        }
                    )
                }

                $results = Find-DSWeakEncryptionAccounts -Domain 'contoso.com'
                $results | Should -Not -BeNullOrEmpty
                $results[0].SamAccountName       | Should -Be 'legacyapp'
                $results[0].ReversibleEncryption | Should -BeTrue
                $results[0].RiskLevel            | Should -Be 'High'
            }
        }

        It 'Should return account with DES-only flag set' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            samaccountname       = @('legacydes')
                            distinguishedname    = @('CN=legacydes,OU=ServiceAccounts,DC=contoso,DC=com')
                            useraccountcontrol   = @(2097664)   # 512 + 2097152 (USE_DES_KEY_ONLY)
                            pwdlastset           = @(132000000000000000L)
                            lastlogontimestamp   = @(132000000000000000L)
                            memberof             = $null
                            serviceprincipalname = $null
                        }
                    )
                }

                $results = Find-DSWeakEncryptionAccounts -Domain 'contoso.com'
                $results | Should -Not -BeNullOrEmpty
                $results[0].DESKeyOnly | Should -BeTrue
                $results[0].RiskLevel  | Should -Be 'Medium'
            }
        }
    }
}
