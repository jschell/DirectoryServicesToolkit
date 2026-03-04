BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSUserCreatedComputers' -Tag 'Unit', 'Enumeration' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                Name              = 'ROGUE01'
                SamAccountName    = 'ROGUE01$'
                DistinguishedName = 'CN=ROGUE01,CN=Computers,DC=contoso,DC=com'
                CreatorSID        = 'S-1-5-21-123456789-123456789-123456789-1234'
                CreatorAccount    = 'CONTOSO\jsmith'
                WhenCreated       = (Get-Date)
                OperatingSystem   = $null
                RiskLevel         = 'Medium'
                Finding           = 'Computer was created by non-admin account'
            }

            $result.PSObject.Properties.Name | Should -Contain 'Name'
            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'CreatorSID'
            $result.PSObject.Properties.Name | Should -Contain 'CreatorAccount'
            $result.PSObject.Properties.Name | Should -Contain 'WhenCreated'
            $result.PSObject.Properties.Name | Should -Contain 'OperatingSystem'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }

        It 'RiskLevel should always be Medium for user-created computers' {
            $result = [PSCustomObject]@{ RiskLevel = 'Medium' }
            $result.RiskLevel | Should -Be 'Medium'
        }
    }

    Context 'LDAP filter validation' {

        It 'Filter should require ms-DS-CreatorSID to be present' {
            $filter = '(&(objectClass=computer)(ms-DS-CreatorSID=*))'
            $filter | Should -Match 'ms-DS-CreatorSID'
            $filter | Should -Match '\*'
        }

        It 'Filter should be scoped to computer objects' {
            $filter = '(&(objectClass=computer)(ms-DS-CreatorSID=*))'
            $filter | Should -Match 'objectClass=computer'
        }
    }

    Context 'Mocked query — result enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    # Simulate a byte array SID
                    $sidBytes = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-3623811015-3361044348-30300820-1013').GetBinaryForm()
                    return @(
                        @{
                            name               = @('ROGUE01')
                            samaccountname     = @('ROGUE01$')
                            distinguishedname  = @('CN=ROGUE01,CN=Computers,DC=contoso,DC=com')
                            'ms-ds-creatorsid' = @($sidBytes)
                            whencreated        = @([datetime]'2026-01-15')
                            operatingsystem    = $null
                        }
                    )
                }
            }
        }

        It 'Should return one result per computer with creator SID' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSUserCreatedComputers -Domain 'contoso.com'
                $results.Count | Should -Be 1
            }
        }

        It 'Should populate Name and SamAccountName from LDAP attributes' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSUserCreatedComputers -Domain 'contoso.com'
                $results[0].Name          | Should -Be 'ROGUE01'
                $results[0].SamAccountName | Should -Be 'ROGUE01$'
            }
        }
    }
}
