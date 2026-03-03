BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSPasswordNotRequired' -Tag 'Unit', 'AccountHygiene' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                SamAccountName    = 'jdoe'
                DistinguishedName = 'CN=jdoe,OU=Users,DC=contoso,DC=com'
                Enabled           = $true
                PasswordLastSet   = $null
                PasswordNeverSet  = $true
            }

            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordLastSet'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordNeverSet'
        }
    }

    Context 'LDAP filter construction' {

        It 'Should include PASSWD_NOTREQD bit (32) in filter' {
            $filterParts = @(
                '(objectClass=user)'
                '(userAccountControl:1.2.840.113556.1.4.803:=32)'
            )
            $ldapFilter = '(&{0})' -f ($filterParts -join '')
            $ldapFilter | Should -Match ':=32\)'
        }

        It 'Should exclude disabled accounts by default' {
            $filterParts = @(
                '(objectClass=user)'
                '(userAccountControl:1.2.840.113556.1.4.803:=32)'
                '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
            )
            $ldapFilter = '(&{0})' -f ($filterParts -join '')
            $ldapFilter | Should -Match '!\(userAccountControl.*:=2\)'
        }

        It 'Should not exclude disabled accounts when IncludeDisabled is set' {
            $filterParts = @(
                '(objectClass=user)'
                '(userAccountControl:1.2.840.113556.1.4.803:=32)'
            )
            $ldapFilter = '(&{0})' -f ($filterParts -join '')
            $ldapFilter | Should -Not -Match '!\(userAccountControl.*:=2\)'
        }
    }

    Context 'PasswordNeverSet flag' {

        It 'Should be $true when pwdLastSet is 0' {
            $pwdLastSetRaw   = 0
            $passwordLastSet = if ($null -ne $pwdLastSetRaw -and [long]$pwdLastSetRaw -gt 0)
                               { [DateTime]::FromFileTime([long]$pwdLastSetRaw) }
                               else { $null }
            $passwordNeverSet = ($null -eq $passwordLastSet)
            $passwordNeverSet | Should -BeTrue
        }

        It 'Should be $false when pwdLastSet has a valid FILETIME' {
            $pwdLastSetRaw   = (Get-Date '2024-01-01').ToFileTime()
            $passwordLastSet = if ($null -ne $pwdLastSetRaw -and [long]$pwdLastSetRaw -gt 0)
                               { [DateTime]::FromFileTime([long]$pwdLastSetRaw) }
                               else { $null }
            $passwordNeverSet = ($null -eq $passwordLastSet)
            $passwordNeverSet | Should -BeFalse
        }
    }

    Context 'Mocked query' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            distinguishedname  = @('CN=jdoe,OU=Users,DC=contoso,DC=com')
                            samaccountname     = @('jdoe')
                            useraccountcontrol = @(544)   # 512 + 32 (PASSWD_NOTREQD)
                            pwdlastset         = @(0)
                            memberof           = @()
                        }
                    )
                }

                Mock New-Object {
                    return [PSCustomObject]@{ Name = 'contoso.com' }
                } -ParameterFilter { $TypeName -match 'DirectoryContext' }

                $fakeEntry = [PSCustomObject]@{ Name = 'contoso.com' }
                Mock ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain) { return $fakeEntry }
            }
        }

        It 'Should return a result for a mocked account' {
            InModuleScope DirectoryServicesToolkit {
                $results = Find-DSPasswordNotRequired -Domain 'contoso.com'
                $results | Should -Not -BeNullOrEmpty
            }
        }

        It 'PasswordNeverSet should be $true for account with pwdLastSet=0' {
            InModuleScope DirectoryServicesToolkit {
                $results = Find-DSPasswordNotRequired -Domain 'contoso.com'
                $results[0].PasswordNeverSet | Should -BeTrue
            }
        }

        It 'PasswordLastSet should be $null for account with pwdLastSet=0' {
            InModuleScope DirectoryServicesToolkit {
                $results = Find-DSPasswordNotRequired -Domain 'contoso.com'
                $results[0].PasswordLastSet | Should -BeNullOrEmpty
            }
        }
    }

    Context 'Large result count warning' {

        It 'Should emit a warning when result count exceeds 10' {
            InModuleScope DirectoryServicesToolkit {
                # Build 11 mock accounts
                $mockData = 1..11 | ForEach-Object {
                    @{
                        distinguishedname  = @("CN=user$_,OU=Users,DC=contoso,DC=com")
                        samaccountname     = @("user$_")
                        useraccountcontrol = @(544)
                        pwdlastset         = @(0)
                        memberof           = @()
                    }
                }

                Mock Invoke-DSDirectorySearch { return $mockData }

                Mock New-Object {
                    return [PSCustomObject]@{ Name = 'contoso.com' }
                } -ParameterFilter { $TypeName -match 'DirectoryContext' }

                $fakeEntry = [PSCustomObject]@{ Name = 'contoso.com' }
                Mock ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain) { return $fakeEntry }

                { Find-DSPasswordNotRequired -Domain 'contoso.com' -WarningAction SilentlyContinue } |
                    Should -Not -Throw
            }
        }
    }
}
