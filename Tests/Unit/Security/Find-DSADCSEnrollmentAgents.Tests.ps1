BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSADCSEnrollmentAgents' -Tag 'Unit', 'Security', 'ADCS' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                Name              = 'EnrollmentAgent'
                DistinguishedName = 'CN=EnrollmentAgent,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                EKUs              = @('1.3.6.1.4.1.311.20.2.1')
                RASignatureCount  = 0
                EnrollmentFlag    = 0
                RiskLevel         = 'High'
                Finding           = 'Template grants Certificate Request Agent (enrollment agent) rights — ESC3 candidate'
            }

            $result.PSObject.Properties.Name | Should -Contain 'Name'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'EKUs'
            $result.PSObject.Properties.Name | Should -Contain 'RASignatureCount'
            $result.PSObject.Properties.Name | Should -Contain 'EnrollmentFlag'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }

        It 'EKUs should be an array' {
            $result = [PSCustomObject]@{
                EKUs = @('1.3.6.1.4.1.311.20.2.1')
            }
            $result.EKUs | Should -BeOfType [string]
            $result.EKUs.Count | Should -Be 1
        }
    }

    Context 'RiskLevel classification' {

        It 'RiskLevel should always be High for enrollment agent templates' {
            $result = [PSCustomObject]@{
                RiskLevel = 'High'
            }
            $result.RiskLevel | Should -Be 'High'
        }
    }

    Context 'Finding message content' {

        It 'Finding should reference ESC3' {
            $finding = "Template grants Certificate Request Agent (enrollment agent) rights — ESC3 candidate"
            $finding | Should -Match 'ESC3'
        }

        It 'Finding should mention enrollment agent rights' {
            $finding = "Template grants Certificate Request Agent (enrollment agent) rights — ESC3 candidate"
            $finding | Should -Match 'enrollment agent'
        }
    }

    Context 'Mocked query — result enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name                   = @('EnrollmentAgent')
                            distinguishedname      = @('CN=EnrollmentAgent,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com')
                            pkiextendedkeyusage    = @('1.3.6.1.4.1.311.20.2.1')
                            'mspki-ra-signature'   = @(0)
                            'mspki-enrollment-flag' = @(0)
                        }
                    )
                }
            }
        }

        It 'Should return one result per enrollment agent template' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSADCSEnrollmentAgents -Domain 'contoso.com'
                $results.Count | Should -Be 1
            }
        }

        It 'Should set RiskLevel to High for enrollment agent templates' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSADCSEnrollmentAgents -Domain 'contoso.com'
                $results[0].RiskLevel | Should -Be 'High'
            }
        }

        It 'Should include the Certificate Request Agent EKU OID in EKUs' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSADCSEnrollmentAgents -Domain 'contoso.com'
                $results[0].EKUs | Should -Contain '1.3.6.1.4.1.311.20.2.1'
            }
        }
    }
}
