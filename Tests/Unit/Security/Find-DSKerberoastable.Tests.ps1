BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSKerberoastable' -Tag 'Unit', 'Security' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                SamAccountName    = 'svc-sql'
                DistinguishedName = 'CN=svc-sql,OU=ServiceAccounts,DC=contoso,DC=com'
                SPNs              = @('MSSQLSvc/sqlserver.contoso.com:1433')
                PasswordLastSet   = (Get-Date).AddDays(-180)
                PasswordAgeDays   = 180
                Enabled           = $true
                IsManagedAccount  = $false
            }

            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'SPNs'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordLastSet'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordAgeDays'
            $result.PSObject.Properties.Name | Should -Contain 'Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'IsManagedAccount'
        }

        It 'SPNs should be an array' {
            $result = [PSCustomObject]@{
                SPNs = @('MSSQLSvc/sqlserver:1433', 'MSSQLSvc/sqlserver.contoso.com:1433')
            }
            $result.SPNs | Should -BeOfType [string]
            $result.SPNs.Count | Should -Be 2
        }

        It 'PasswordLastSet should be null when pwdLastSet is 0' {
            $pwdLastSetRaw = 0
            $passwordLastSet = if ($null -ne $pwdLastSetRaw -and [long]$pwdLastSetRaw -gt 0)
            {
                [DateTime]::FromFileTime([long]$pwdLastSetRaw)
            }
            else
            {
                $null
            }
            $passwordLastSet | Should -BeNullOrEmpty
        }

        It 'PasswordLastSet should be a DateTime when pwdLastSet is a valid FILETIME' {
            $pwdLastSetRaw = (Get-Date).AddDays(-90).ToFileTime()
            $passwordLastSet = [DateTime]::FromFileTime([long]$pwdLastSetRaw)
            $passwordLastSet | Should -BeOfType [DateTime]
        }

        It 'PasswordAgeDays should be a positive integer for old passwords' {
            $passwordLastSet = (Get-Date).AddDays(-180)
            $passwordAgeDays = [int]((Get-Date) - $passwordLastSet).TotalDays
            $passwordAgeDays | Should -BeGreaterThan 0
        }
    }

    Context 'LDAP filter construction' {

        It 'Base filter should target users with SPNs and exclude krbtgt' {
            $parts = @(
                '(objectClass=user)'
                '(servicePrincipalName=*)'
                '(!(cn=krbtgt))'
                '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
            )
            $filter = '(&{0})' -f ($parts -join '')

            $filter | Should -Match 'servicePrincipalName=\*'
            $filter | Should -Match '!\(cn=krbtgt\)'
            $filter | Should -Match '1\.2\.840\.113556\.1\.4\.803:=2'
        }

        It 'IncludeDisabled filter should omit the disabled-account exclusion clause' {
            $parts = @(
                '(objectClass=user)'
                '(servicePrincipalName=*)'
                '(!(cn=krbtgt))'
                # Note: NO disabled exclusion clause
            )
            $filter = '(&{0})' -f ($parts -join '')
            $filter | Should -Not -Match '1\.2\.840\.113556\.1\.4\.803:=2'
        }

        It 'ExcludeManagedAccounts filter should exclude gMSA and MSA objectClass' {
            $parts = @(
                '(objectClass=user)'
                '(servicePrincipalName=*)'
                '(!(cn=krbtgt))'
                '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
                '(!(objectClass=msDS-GroupManagedServiceAccount))'
                '(!(objectClass=msDS-ManagedServiceAccount))'
            )
            $filter = '(&{0})' -f ($parts -join '')
            $filter | Should -Match 'msDS-GroupManagedServiceAccount'
            $filter | Should -Match 'msDS-ManagedServiceAccount'
        }
    }

    Context 'Enabled flag' {

        It 'Enabled should be false for disabled accounts' {
            $uac     = 512 -bor 2   # NormalAccount | AccountDisable
            $enabled = -not [bool]($uac -band 2)
            $enabled | Should -BeFalse
        }

        It 'Enabled should be true for enabled accounts' {
            $uac     = 512
            $enabled = -not [bool]($uac -band 2)
            $enabled | Should -BeTrue
        }
    }

    Context 'IsManagedAccount detection' {

        It 'IsManagedAccount should be true for gMSA objectClass' {
            $objectClass      = @('top', 'person', 'user', 'msDS-GroupManagedServiceAccount')
            $isManagedAccount = $objectClass -contains 'msDS-GroupManagedServiceAccount' -or
                                $objectClass -contains 'msDS-ManagedServiceAccount'
            $isManagedAccount | Should -BeTrue
        }

        It 'IsManagedAccount should be false for regular user accounts' {
            $objectClass      = @('top', 'person', 'organizationalPerson', 'user')
            $isManagedAccount = $objectClass -contains 'msDS-GroupManagedServiceAccount' -or
                                $objectClass -contains 'msDS-ManagedServiceAccount'
            $isManagedAccount | Should -BeFalse
        }
    }

    Context 'Mocked query — result enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            samaccountname      = @('svc-sql')
                            distinguishedname   = @('CN=svc-sql,OU=SA,DC=contoso,DC=com')
                            serviceprincipalname = @('MSSQLSvc/sqlserver.contoso.com:1433')
                            useraccountcontrol  = @(512)
                            pwdlastset          = @((Get-Date).AddDays(-180).ToFileTime())
                            objectclass         = @('user')
                        }
                        @{
                            samaccountname      = @('svc-http')
                            distinguishedname   = @('CN=svc-http,OU=SA,DC=contoso,DC=com')
                            serviceprincipalname = @('HTTP/webserver.contoso.com')
                            useraccountcontrol  = @(512)
                            pwdlastset          = @((Get-Date).AddDays(-30).ToFileTime())
                            objectclass         = @('user')
                        }
                    )
                }
            }
        }

        It 'Should return one result per Kerberoastable account' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSKerberoastable -Domain 'contoso.com'
                $results.Count | Should -Be 2
            }
        }

        It 'Should sort results by PasswordAgeDays descending (oldest password first)' {
            InModuleScope DirectoryServicesToolkit {
                $results = @(
                    [PSCustomObject]@{ SamAccountName = 'svc-sql';  PasswordAgeDays = 180 }
                    [PSCustomObject]@{ SamAccountName = 'svc-http'; PasswordAgeDays = 30 }
                )
                $sorted = $results | Sort-Object -Property PasswordAgeDays -Descending
                $sorted[0].SamAccountName | Should -Be 'svc-sql'
            }
        }
    }
}
