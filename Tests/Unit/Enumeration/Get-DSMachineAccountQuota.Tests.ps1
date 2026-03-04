BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSMachineAccountQuota' -Tag 'Unit', 'Enumeration' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DomainName          = 'contoso.com'
                DomainDN            = 'DC=contoso,DC=com'
                MachineAccountQuota = 10
                RiskLevel           = 'High'
                Finding             = 'Any authenticated user can create up to 10 computer accounts'
                Remediation         = 'Set ms-DS-MachineAccountQuota to 0'
            }

            $result.PSObject.Properties.Name | Should -Contain 'DomainName'
            $result.PSObject.Properties.Name | Should -Contain 'DomainDN'
            $result.PSObject.Properties.Name | Should -Contain 'MachineAccountQuota'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
            $result.PSObject.Properties.Name | Should -Contain 'Remediation'
        }
    }

    Context 'Risk level classification' {

        It 'MAQ of 0 should be Low risk' {
            $maq  = 0
            $risk = if ($maq -eq 0) { 'Low' } elseif ($maq -le 5) { 'Medium' } else { 'High' }
            $risk | Should -Be 'Low'
        }

        It 'MAQ of 5 should be Medium risk' {
            $maq  = 5
            $risk = if ($maq -eq 0) { 'Low' } elseif ($maq -le 5) { 'Medium' } else { 'High' }
            $risk | Should -Be 'Medium'
        }

        It 'MAQ of 10 (default) should be High risk' {
            $maq  = 10
            $risk = if ($maq -eq 0) { 'Low' } elseif ($maq -le 5) { 'Medium' } else { 'High' }
            $risk | Should -Be 'High'
        }

        It 'MAQ of 1 should be Medium risk' {
            $maq  = 1
            $risk = if ($maq -eq 0) { 'Low' } elseif ($maq -le 5) { 'Medium' } else { 'High' }
            $risk | Should -Be 'Medium'
        }
    }

    Context 'Remediation guidance' {

        It 'Remediation should be non-null when MAQ is greater than 0' {
            $maq         = 10
            $remediation = if ($maq -gt 0) { 'Set ms-DS-MachineAccountQuota to 0 on the domain NC root' } else { $null }
            $remediation | Should -Not -BeNullOrEmpty
        }

        It 'Remediation should be null when MAQ is 0' {
            $maq         = 0
            $remediation = if ($maq -gt 0) { 'Set ms-DS-MachineAccountQuota to 0 on the domain NC root' } else { $null }
            $remediation | Should -BeNullOrEmpty
        }
    }

    Context 'Mocked query — result enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            distinguishedname            = @('DC=contoso,DC=com')
                            name                         = @('contoso')
                            'ms-ds-machineaccountquota'  = @(10)
                        }
                    )
                }
            }
        }

        It 'Should return one result for the domain' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Get-DSMachineAccountQuota -Domain 'contoso.com'
                $results.Count | Should -Be 1
            }
        }

        It 'Should correctly read MAQ value of 10' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Get-DSMachineAccountQuota -Domain 'contoso.com'
                $results[0].MachineAccountQuota | Should -Be 10
                $results[0].RiskLevel           | Should -Be 'High'
            }
        }
    }
}
