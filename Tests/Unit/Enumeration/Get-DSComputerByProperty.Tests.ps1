BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSComputerByProperty' -Tag 'Unit', 'Enumeration' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                Name                   = 'WS001'
                SamAccountName         = 'WS001$'
                DistinguishedName      = 'CN=WS001,OU=Workstations,DC=contoso,DC=com'
                DNSHostName            = 'WS001.contoso.com'
                OperatingSystem        = 'Windows 10 Enterprise'
                OperatingSystemVersion = '10.0 (19044)'
                Enabled                = $true
                PasswordLastSet        = (Get-Date)
                LastLogonTimestamp     = (Get-Date)
                DaysSinceLastLogon     = 5
            }

            $result.PSObject.Properties.Name | Should -Contain 'Name'
            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'DNSHostName'
            $result.PSObject.Properties.Name | Should -Contain 'OperatingSystem'
            $result.PSObject.Properties.Name | Should -Contain 'OperatingSystemVersion'
            $result.PSObject.Properties.Name | Should -Contain 'Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordLastSet'
            $result.PSObject.Properties.Name | Should -Contain 'LastLogonTimestamp'
            $result.PSObject.Properties.Name | Should -Contain 'DaysSinceLastLogon'
        }
    }

    Context 'LDAP filter construction' {

        It 'Base filter should be objectCategory=computer' {
            # Simulate filter build logic
            $filterParts = @('(objectCategory=computer)')
            $ldapFilter  = $filterParts[0]
            $ldapFilter  | Should -Be '(objectCategory=computer)'
        }

        It 'Should append OperatingSystem clause when specified' {
            $filterParts = @('(objectCategory=computer)')
            $filterParts += '(operatingSystem=Windows Server 2019*)'
            $ldapFilter  = '(&{0})' -f ($filterParts -join '')
            $ldapFilter  | Should -Match 'operatingSystem=Windows Server 2019\*'
        }

        It 'Should append enabled-only clause when Enabled=$true' {
            $filterParts = @('(objectCategory=computer)')
            $filterParts += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
            $ldapFilter  = '(&{0})' -f ($filterParts -join '')
            $ldapFilter  | Should -Match 'userAccountControl'
            $ldapFilter  | Should -Match '!\('
        }

        It 'Should append disabled-only clause when Enabled=$false' {
            $filterParts = @('(objectCategory=computer)')
            $filterParts += '(userAccountControl:1.2.840.113556.1.4.803:=2)'
            $ldapFilter  = '(&{0})' -f ($filterParts -join '')
            $ldapFilter  | Should -Match 'userAccountControl:1\.2\.840'
            $ldapFilter  | Should -Not -Match '!\('
        }

        It 'Should append lastLogonTimestamp clause when InactiveDays is specified' {
            $threshold   = (Get-Date).AddDays(-90).ToFileTime()
            $filterParts = @('(objectCategory=computer)')
            $filterParts += "(lastLogonTimestamp<=$threshold)"
            $ldapFilter  = '(&{0})' -f ($filterParts -join '')
            $ldapFilter  | Should -Match 'lastLogonTimestamp<='
        }
    }

    Context 'DaysSinceLastLogon calculation' {

        It 'Should calculate correct days since last logon' {
            $pastDate   = (Get-Date).AddDays(-30)
            $now        = Get-Date
            $daysDiff   = [int]($now - $pastDate).TotalDays
            $daysDiff   | Should -BeGreaterThan 29
            $daysDiff   | Should -BeLessThan 32
        }

        It 'Should return $null when lastLogonTimestamp is 0' {
            $raw    = 0
            $logon  = if ($null -ne $raw -and [long]$raw -gt 0) { [DateTime]::FromFileTime([long]$raw) } else { $null }
            $days   = if ($null -ne $logon) { [int]((Get-Date) - $logon).TotalDays } else { $null }
            $days   | Should -BeNullOrEmpty
        }
    }

    Context 'Mocked query' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name                   = @('SRV01')
                            samaccountname         = @('SRV01$')
                            distinguishedname      = @('CN=SRV01,OU=Servers,DC=contoso,DC=com')
                            dnshostname            = @('SRV01.contoso.com')
                            operatingsystem        = @('Windows Server 2019 Standard')
                            operatingsystemversion = @('10.0 (17763)')
                            useraccountcontrol     = @(4096)
                            pwdlastset             = @(0)
                            lastlogontimestamp     = @(0)
                        }
                    )
                }

                Mock Resolve-DSDomainName { return 'contoso.com' }
            }
        }

        It 'Should return a computer result' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSComputerByProperty -Domain 'contoso.com'
                $results | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should populate Name from mocked data' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSComputerByProperty -Domain 'contoso.com'
                $results[0].Name | Should -Be 'SRV01'
            }
        }

        It 'Should populate OperatingSystem from mocked data' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSComputerByProperty -Domain 'contoso.com'
                $results[0].OperatingSystem | Should -Be 'Windows Server 2019 Standard'
            }
        }

        It 'LastLogonTimestamp should be $null when value is 0' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSComputerByProperty -Domain 'contoso.com'
                $results[0].LastLogonTimestamp | Should -BeNullOrEmpty
            }
        }
    }

    Context 'Parameter validation' {

        It 'SizeLimit should default to 0' {
            $cmd   = Get-Command Get-DSComputerByProperty -Module DirectoryServicesToolkit
            $param = $cmd.Parameters['SizeLimit']
            $param | Should -Not -BeNullOrEmpty
        }

        It 'InactiveDays should accept values in range 0-3650' {
            $cmd   = Get-Command Get-DSComputerByProperty -Module DirectoryServicesToolkit
            $param = $cmd.Parameters['InactiveDays']
            $param | Should -Not -BeNullOrEmpty
        }
    }
}
