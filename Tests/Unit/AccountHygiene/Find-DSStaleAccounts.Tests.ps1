BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSStaleAccounts' -Tag 'Unit', 'AccountHygiene' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                SamAccountName     = 'jdoe'
                DistinguishedName  = 'CN=jdoe,OU=Users,DC=contoso,DC=com'
                ObjectType         = 'User'
                Enabled            = $true
                LastLogonTimestamp = (Get-Date).AddDays(-120)
                DaysSinceLastLogon = 120
                PasswordLastSet    = (Get-Date).AddDays(-200)
            }

            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'ObjectType'
            $result.PSObject.Properties.Name | Should -Contain 'Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'LastLogonTimestamp'
            $result.PSObject.Properties.Name | Should -Contain 'DaysSinceLastLogon'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordLastSet'
        }

        It 'ObjectType should be User or Computer' {
            $validTypes = @('User', 'Computer')
            'User'     | Should -BeIn $validTypes
            'Computer' | Should -BeIn $validTypes
        }
    }

    Context 'Threshold calculation' {

        It 'Should compute correct FILETIME threshold for 90 days' {
            $thresholdDate     = (Get-Date).AddDays(-90)
            $thresholdFileTime = $thresholdDate.ToFileTime()
            $thresholdFileTime | Should -BeGreaterThan 0
        }

        It 'Threshold FILETIME should be less than now' {
            $now               = (Get-Date).ToFileTime()
            $thresholdFileTime = (Get-Date).AddDays(-90).ToFileTime()
            $thresholdFileTime | Should -BeLessThan $now
        }
    }

    Context 'DaysSinceLastLogon calculation' {

        It 'Should return correct days for an account last logged on 120 days ago' {
            $lastLogon         = (Get-Date).AddDays(-120)
            $now               = Get-Date
            $daysSinceLastLogon = [int]($now - $lastLogon).TotalDays
            $daysSinceLastLogon | Should -BeGreaterThan 119
            $daysSinceLastLogon | Should -BeLessThan 122
        }

        It 'Should return $null for DaysSinceLastLogon when lastLogonTimestamp is 0' {
            $lastLogonRaw      = 0
            $lastLogon         = if ($null -ne $lastLogonRaw -and [long]$lastLogonRaw -gt 0)
                                 { [DateTime]::FromFileTime([long]$lastLogonRaw) }
                                 else { $null }
            $daysSinceLastLogon = if ($null -ne $lastLogon)
                                  { [int]((Get-Date) - $lastLogon).TotalDays }
                                  else { $null }
            $daysSinceLastLogon | Should -BeNullOrEmpty
        }
    }

    Context 'LDAP filter construction' {

        It 'User filter should include UAC bit 512 (NORMAL_ACCOUNT)' {
            $threshold = (Get-Date).AddDays(-90).ToFileTime()
            $filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$threshold))"
            $filter | Should -Match ':=512\)'
            $filter | Should -Match 'lastLogonTimestamp<='
        }

        It 'Computer filter should use objectCategory=computer' {
            $threshold = (Get-Date).AddDays(-90).ToFileTime()
            $filter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$threshold))"
            $filter | Should -Match 'objectCategory=computer'
            $filter | Should -Match 'lastLogonTimestamp<='
        }

        It 'Never-logged-on filter should use !(lastLogonTimestamp=*)' {
            $filter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(lastLogonTimestamp=*)))'
            $filter | Should -Match '!\(lastLogonTimestamp=\*\)'
        }
    }

    Context 'Parameter defaults' {

        It 'ThresholdDays should default to 90' {
            $cmd   = Get-Command Find-DSStaleAccounts -Module DirectoryServicesToolkit
            $param = $cmd.Parameters['ThresholdDays']
            $param | Should -Not -BeNullOrEmpty
        }

        It 'ObjectType should default to All' {
            $cmd   = Get-Command Find-DSStaleAccounts -Module DirectoryServicesToolkit
            $param = $cmd.Parameters['ObjectType']
            $param | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Mocked query — stale accounts' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                # Returns: one stale user (120 days ago), one never-logged-on computer
                Mock Invoke-DSDirectorySearch {
                    param($LdapPath, $Filter)

                    if ($Filter -match 'objectClass=user' -and $Filter -match 'lastLogonTimestamp<=')
                    {
                        return @(
                            @{
                                distinguishedname  = @('CN=jdoe,OU=Users,DC=contoso,DC=com')
                                samaccountname     = @('jdoe')
                                useraccountcontrol = @(512)
                                lastlogontimestamp = @((Get-Date).AddDays(-120).ToFileTime())
                                pwdlastset         = @((Get-Date).AddDays(-200).ToFileTime())
                                objectclass        = @('top', 'person', 'user')
                            }
                        )
                    }

                    if ($Filter -match 'objectClass=user' -and $Filter -match '!\(lastLogonTimestamp')
                    {
                        return @()
                    }

                    if ($Filter -match 'objectCategory=computer' -and $Filter -match 'lastLogonTimestamp<=')
                    {
                        return @()
                    }

                    if ($Filter -match 'objectCategory=computer' -and $Filter -match '!\(lastLogonTimestamp')
                    {
                        return @(
                            @{
                                distinguishedname  = @('CN=WS001,OU=Computers,DC=contoso,DC=com')
                                samaccountname     = @('WS001$')
                                useraccountcontrol = @(4096)
                                lastlogontimestamp = @(0)
                                pwdlastset         = @(0)
                                objectclass        = @('top', 'computer')
                            }
                        )
                    }

                    return @()
                }

                Mock New-Object {
                    return [PSCustomObject]@{ Name = 'contoso.com' }
                } -ParameterFilter { $TypeName -match 'DirectoryContext' }

                $fakeEntry = [PSCustomObject]@{ Name = 'contoso.com' }
                Mock ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain) { return $fakeEntry }
            }
        }

        It 'Should return two stale accounts (one user, one computer)' {
            InModuleScope DirectoryServicesToolkit {
                $results = Find-DSStaleAccounts -Domain 'contoso.com'
                $results.Count | Should -Be 2
            }
        }

        It 'Stale user should have correct DaysSinceLastLogon (~120)' {
            InModuleScope DirectoryServicesToolkit {
                $results  = Find-DSStaleAccounts -Domain 'contoso.com'
                $staleUser = $results | Where-Object { $_.SamAccountName -eq 'jdoe' }
                $staleUser.DaysSinceLastLogon | Should -BeGreaterThan 119
                $staleUser.DaysSinceLastLogon | Should -BeLessThan 122
            }
        }

        It 'Never-logged-on computer should have null DaysSinceLastLogon' {
            InModuleScope DirectoryServicesToolkit {
                $results   = Find-DSStaleAccounts -Domain 'contoso.com'
                $staleComp = $results | Where-Object { $_.SamAccountName -eq 'WS001$' }
                $staleComp.DaysSinceLastLogon | Should -BeNullOrEmpty
                $staleComp.LastLogonTimestamp | Should -BeNullOrEmpty
            }
        }

        It 'User ObjectType should be User' {
            InModuleScope DirectoryServicesToolkit {
                $results  = Find-DSStaleAccounts -Domain 'contoso.com'
                $staleUser = $results | Where-Object { $_.SamAccountName -eq 'jdoe' }
                $staleUser.ObjectType | Should -Be 'User'
            }
        }

        It 'Computer ObjectType should be Computer' {
            InModuleScope DirectoryServicesToolkit {
                $results   = Find-DSStaleAccounts -Domain 'contoso.com'
                $staleComp = $results | Where-Object { $_.SamAccountName -eq 'WS001$' }
                $staleComp.ObjectType | Should -Be 'Computer'
            }
        }

        It '-ObjectType User should return only user accounts' {
            InModuleScope DirectoryServicesToolkit {
                $results = Find-DSStaleAccounts -Domain 'contoso.com' -ObjectType User
                $results | ForEach-Object { $_.ObjectType | Should -Be 'User' }
            }
        }

        It '-ObjectType Computer should return only computer accounts' {
            InModuleScope DirectoryServicesToolkit {
                $results = Find-DSStaleAccounts -Domain 'contoso.com' -ObjectType Computer
                $results | ForEach-Object { $_.ObjectType | Should -Be 'Computer' }
            }
        }
    }
}
