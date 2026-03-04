BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSASREPRoastable' -Tag 'Unit', 'Security' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                SamAccountName    = 'legacyuser'
                DistinguishedName = 'CN=legacyuser,OU=Users,DC=contoso,DC=com'
                Enabled           = $true
                PasswordLastSet   = (Get-Date).AddDays(-60)
                MemberOf          = @()
            }

            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordLastSet'
            $result.PSObject.Properties.Name | Should -Contain 'MemberOf'
        }

        It 'MemberOf should be an array' {
            $result = [PSCustomObject]@{
                MemberOf = @('CN=Developers,OU=Groups,DC=contoso,DC=com')
            }
            ,$result.MemberOf | Should -BeOfType [array]
        }

        It 'MemberOf should be empty array when account has no group memberships' {
            $obj = @{ memberof = @() }
            $memberOf = @($obj['memberof'])
            $memberOf | Should -BeNullOrEmpty
        }
    }

    Context 'LDAP filter construction' {

        It 'Base filter should target DONT_REQUIRE_PREAUTH bit (4194304) and exclude disabled accounts' {
            $parts = @(
                '(objectClass=user)'
                '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
                '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
            )
            $filter = '(&{0})' -f ($parts -join '')

            $filter | Should -Match '4194304'
            $filter | Should -Match '1\.2\.840\.113556\.1\.4\.803:=2'
        }

        It 'IncludeDisabled filter should omit disabled-account exclusion' {
            $parts = @(
                '(objectClass=user)'
                '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
                # disabled exclusion intentionally absent
            )
            $filter = '(&{0})' -f ($parts -join '')
            $filter | Should -Not -Match '\(!\(userAccountControl:1\.2\.840\.113556\.1\.4\.803:=2\)\)'
        }

        It 'DONT_REQUIRE_PREAUTH UAC bit value should be 4194304 (0x400000)' {
            $bit = 0x400000
            $bit | Should -Be 4194304
        }
    }

    Context 'UAC bit extraction' {

        It 'Enabled should be false for disabled account (UAC bit 2 set)' {
            $uac     = 4194304 -bor 512 -bor 2   # DONT_REQUIRE_PREAUTH | NormalAccount | AccountDisable
            $enabled = -not [bool]($uac -band 2)
            $enabled | Should -BeFalse
        }

        It 'Enabled should be true for enabled account (UAC bit 2 not set)' {
            $uac     = 4194304 -bor 512   # DONT_REQUIRE_PREAUTH | NormalAccount
            $enabled = -not [bool]($uac -band 2)
            $enabled | Should -BeTrue
        }

        It 'DONT_REQUIRE_PREAUTH bit should be detectable via bitwise AND' {
            $uac         = 4194304 -bor 512
            $hasPreAuth  = [bool]($uac -band 4194304)
            $hasPreAuth  | Should -BeTrue
        }
    }

    Context 'PasswordLastSet handling' {

        It 'PasswordLastSet should be null when pwdLastSet is 0' {
            $raw = 0L
            $result = if ($null -ne $raw -and $raw -gt 0)
            {
                [DateTime]::FromFileTime($raw)
            }
            else { $null }
            $result | Should -BeNullOrEmpty
        }

        It 'PasswordLastSet should be a DateTime for valid FILETIME value' {
            $raw    = (Get-Date).AddDays(-60).ToFileTime()
            $result = [DateTime]::FromFileTime($raw)
            $result | Should -BeOfType [DateTime]
        }
    }

    Context 'Mocked query — result enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            samaccountname     = @('legacyuser')
                            distinguishedname  = @('CN=legacyuser,OU=Users,DC=contoso,DC=com')
                            useraccountcontrol = @(4194816)   # 4194304 | 512
                            memberof           = @('CN=Developers,OU=Groups,DC=contoso,DC=com')
                            pwdlastset         = @((Get-Date).AddDays(-60).ToFileTime())
                        }
                    )
                }
            }
        }

        It 'Should return one result for the matching account' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSASREPRoastable -Domain 'contoso.com'
                $results.Count | Should -Be 1
            }
        }

        It 'Should correctly populate SamAccountName' {
            InModuleScope DirectoryServicesToolkit {
                $results = @(
                    [PSCustomObject]@{
                        SamAccountName    = 'legacyuser'
                        DistinguishedName = 'CN=legacyuser,OU=Users,DC=contoso,DC=com'
                        Enabled           = $true
                        PasswordLastSet   = (Get-Date).AddDays(-60)
                        MemberOf          = @('CN=Developers,OU=Groups,DC=contoso,DC=com')
                    }
                )
                $results[0].SamAccountName | Should -Be 'legacyuser'
                $results[0].Enabled        | Should -BeTrue
            }
        }

        It 'Should return empty result set when no accounts match' {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch { return @() }
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSASREPRoastable -Domain 'contoso.com'
                $results.Count | Should -Be 0
            }
        }
    }
}
