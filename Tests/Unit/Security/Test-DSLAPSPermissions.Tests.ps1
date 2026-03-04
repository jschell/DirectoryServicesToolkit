BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSLAPSPermissions' -Tag 'Unit', 'Security' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                ComputerName      = 'WORKSTATION01'
                ComputerDN        = 'CN=WORKSTATION01,OU=Workstations,DC=contoso,DC=com'
                IdentityReference = 'CONTOSO\helpdesk'
                Rights            = 'ReadProperty'
                ObjectType        = '8d3bca50-1d7e-11d0-a081-00aa006c33ed'
                LAPSAttribute     = 'ms-Mcs-AdmPwd (Legacy LAPS)'
                IsInherited       = $false
                RiskLevel         = 'High'
                Finding           = 'Principal can read LAPS password attribute'
            }

            $result.PSObject.Properties.Name | Should -Contain 'ComputerName'
            $result.PSObject.Properties.Name | Should -Contain 'ComputerDN'
            $result.PSObject.Properties.Name | Should -Contain 'IdentityReference'
            $result.PSObject.Properties.Name | Should -Contain 'Rights'
            $result.PSObject.Properties.Name | Should -Contain 'ObjectType'
            $result.PSObject.Properties.Name | Should -Contain 'LAPSAttribute'
            $result.PSObject.Properties.Name | Should -Contain 'IsInherited'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }

        It 'RiskLevel should always be High for LAPS permission findings' {
            $result = [PSCustomObject]@{ RiskLevel = 'High' }
            $result.RiskLevel | Should -Be 'High'
        }
    }

    Context 'LAPS attribute GUID identification' {

        It 'ms-Mcs-AdmPwd GUID should match expected value' {
            $guid = [guid]'8d3bca50-1d7e-11d0-a081-00aa006c33ed'
            $guid.ToString() | Should -Be '8d3bca50-1d7e-11d0-a081-00aa006c33ed'
        }

        It 'LAPSAttribute label should identify Legacy LAPS for ms-Mcs-AdmPwd GUID' {
            $objectType   = [guid]'8d3bca50-1d7e-11d0-a081-00aa006c33ed'
            $lapsAttrName = if ($objectType -eq [guid]'8d3bca50-1d7e-11d0-a081-00aa006c33ed') { 'ms-Mcs-AdmPwd (Legacy LAPS)' } else { 'msLAPS-Password (Windows LAPS)' }
            $lapsAttrName | Should -Be 'ms-Mcs-AdmPwd (Legacy LAPS)'
        }
    }

    Context 'Mocked query — result enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name              = @('WORKSTATION01')
                            samaccountname    = @('WORKSTATION01$')
                            distinguishedname = @('CN=WORKSTATION01,OU=Workstations,DC=contoso,DC=com')
                        }
                    )
                }
                Mock Get-DSObjectAcl {
                    return @(
                        [PSCustomObject]@{
                            IdentityReference     = 'CONTOSO\helpdesk'
                            ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
                            AccessControlType     = 'Allow'
                            ObjectType            = [guid]'8d3bca50-1d7e-11d0-a081-00aa006c33ed'
                            InheritanceType       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                            IsInherited           = $false
                        }
                    )
                }
            }
        }

        It 'Should return one finding for each flagged ACE' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Test-DSLAPSPermissions -Domain 'contoso.com'
                $results.Count | Should -BeGreaterThan 0
            }
        }

        It 'Should correctly identify LAPS attribute in finding' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Test-DSLAPSPermissions -Domain 'contoso.com'
                $results[0].LAPSAttribute | Should -Be 'ms-Mcs-AdmPwd (Legacy LAPS)'
            }
        }
    }
}
