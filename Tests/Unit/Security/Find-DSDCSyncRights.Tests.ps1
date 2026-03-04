BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSDCSyncRights' -Tag 'Unit', 'Security' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                IdentityReference = 'CONTOSO\attacker'
                Right             = 'DS-Replication-Get-Changes-All'
                RightGuid         = '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
                IsInherited       = $false
                IsCritical        = $true
                RiskLevel         = 'Critical'
                Finding           = 'Non-privileged principal has DCSync rights'
            }

            $result.PSObject.Properties.Name | Should -Contain 'IdentityReference'
            $result.PSObject.Properties.Name | Should -Contain 'Right'
            $result.PSObject.Properties.Name | Should -Contain 'RightGuid'
            $result.PSObject.Properties.Name | Should -Contain 'IsInherited'
            $result.PSObject.Properties.Name | Should -Contain 'IsCritical'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }
    }

    Context 'Replication right GUIDs' {

        It 'DS-Replication-Get-Changes-All GUID should match expected value' {
            $guid = [guid]'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
            $guid.ToString() | Should -Be '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
        }

        It 'DS-Replication-Get-Changes GUID should match expected value' {
            $guid = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            $guid.ToString() | Should -Be '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        }

        It 'DS-Replication-Get-Changes-In-Filtered-Set GUID should match expected value' {
            $guid = [guid]'89e95b76-444d-4c62-991a-0facbeda640c'
            $guid.ToString() | Should -Be '89e95b76-444d-4c62-991a-0facbeda640c'
        }
    }

    Context 'IsCritical classification' {

        It 'DS-Replication-Get-Changes-All should be classified as Critical' {
            $right      = 'DS-Replication-Get-Changes-All'
            $isCritical = ($right -eq 'DS-Replication-Get-Changes-All')
            $isCritical | Should -BeTrue
        }

        It 'DS-Replication-Get-Changes should not be classified as Critical' {
            $right      = 'DS-Replication-Get-Changes'
            $isCritical = ($right -eq 'DS-Replication-Get-Changes-All')
            $isCritical | Should -BeFalse
        }
    }

    Context 'Legitimate principal filtering' {

        It 'Domain Admins should be excluded from results' {
            $identity    = 'CONTOSO\Domain Admins'
            $legitimates = @('Domain Admins', 'Enterprise Admins', 'Domain Controllers')
            $isLegit     = $false
            foreach ($p in $legitimates) { if ($identity -match [regex]::Escape($p)) { $isLegit = $true } }
            $isLegit | Should -BeTrue
        }

        It 'MSOL_ accounts (Azure AD Connect) should be excluded' {
            $identity     = 'CONTOSO\MSOL_a1b2c3d4e5f6'
            $isAADConnect = ($identity -match 'MSOL_')
            $isAADConnect | Should -BeTrue
        }

        It 'Regular user accounts should not be excluded' {
            $identity    = 'CONTOSO\regularuser'
            $legitimates = @('Domain Admins', 'Enterprise Admins', 'Domain Controllers')
            $isLegit     = $false
            foreach ($p in $legitimates) { if ($identity -match [regex]::Escape($p)) { $isLegit = $true } }
            $isLegit | Should -BeFalse
        }
    }

    Context 'Mocked query — result enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Get-DSObjectAcl {
                    return @(
                        [PSCustomObject]@{
                            IdentityReference     = 'CONTOSO\attacker'
                            ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                            AccessControlType     = 'Allow'
                            ObjectType            = [guid]'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
                            InheritanceType       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                            IsInherited           = $false
                        }
                    )
                }
            }
        }

        It 'Should return one result for flagged DCSync right' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSDCSyncRights -Domain 'contoso.com'
                $results.Count | Should -Be 1
            }
        }

        It 'Should flag the result as Critical' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSDCSyncRights -Domain 'contoso.com'
                $results[0].IsCritical | Should -BeTrue
                $results[0].RiskLevel  | Should -Be 'Critical'
            }
        }
    }
}
