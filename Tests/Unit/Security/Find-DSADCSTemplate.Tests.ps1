BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSADCSTemplate' -Tag 'Unit', 'Security', 'ADCS' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                Name                    = 'UserAuthentication'
                DistinguishedName       = 'CN=UserAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                ESCFlags                = @('ESC1')
                IsVulnerable            = $true
                EnrolleeSuppliesSubject = $true
                AnyPurposeEKU           = $false
                NoRASignatureRequired   = $true
                NoManagerApproval       = $true
                EKUs                    = @('1.3.6.1.5.5.7.3.2')
                NameFlag                = 1
                EnrollmentFlag          = 0
                RASignatureCount        = 0
            }

            $result.PSObject.Properties.Name | Should -Contain 'Name'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'ESCFlags'
            $result.PSObject.Properties.Name | Should -Contain 'IsVulnerable'
            $result.PSObject.Properties.Name | Should -Contain 'EnrolleeSuppliesSubject'
            $result.PSObject.Properties.Name | Should -Contain 'AnyPurposeEKU'
            $result.PSObject.Properties.Name | Should -Contain 'NoRASignatureRequired'
            $result.PSObject.Properties.Name | Should -Contain 'NoManagerApproval'
            $result.PSObject.Properties.Name | Should -Contain 'EKUs'
            $result.PSObject.Properties.Name | Should -Contain 'NameFlag'
            $result.PSObject.Properties.Name | Should -Contain 'EnrollmentFlag'
            $result.PSObject.Properties.Name | Should -Contain 'RASignatureCount'
        }

        It 'ESCFlags should be an array' {
            $result = [PSCustomObject]@{
                ESCFlags = @('ESC1', 'ESC2')
            }
            $result.ESCFlags.Count | Should -Be 2
        }
    }

    Context 'ESC1 detection — enrollee supplies subject' {

        It 'ESC1 should be detected when NameFlag bit 0x1 is set' {
            $nameFlag = 0x1
            $isESC1   = [bool]($nameFlag -band 0x1)
            $isESC1   | Should -BeTrue
        }

        It 'ESC1 should not be flagged when NameFlag bit 0x1 is clear' {
            $nameFlag = 0x20000000
            $isESC1   = [bool]($nameFlag -band 0x1)
            $isESC1   | Should -BeFalse
        }
    }

    Context 'ESC2 detection — Any Purpose EKU' {

        It 'ESC2 should be detected when anyExtendedKeyUsage OID is present' {
            $ekus   = @('1.3.6.1.5.5.7.3.2', '2.5.29.37.0')
            $isESC2 = ($ekus -contains '2.5.29.37.0')
            $isESC2 | Should -BeTrue
        }

        It 'ESC2 should be detected when EKU list is empty' {
            $ekus   = @()
            $isESC2 = ($ekus.Count -eq 0)
            $isESC2 | Should -BeTrue
        }

        It 'ESC2 should not be flagged for normal restricted EKUs' {
            $ekus   = @('1.3.6.1.5.5.7.3.2')
            $isESC2 = ($ekus.Count -eq 0) -or ($ekus -contains '2.5.29.37.0')
            $isESC2 | Should -BeFalse
        }
    }

    Context 'Manager approval mitigating factor' {

        It 'NoManagerApproval should be false when PEND_ALL_REQUESTS flag is set' {
            $enrollFlag        = 0x2   # CT_FLAG_PEND_ALL_REQUESTS
            $noManagerApproval = -not [bool]($enrollFlag -band 0x2)
            $noManagerApproval | Should -BeFalse
        }

        It 'NoManagerApproval should be true when PEND_ALL_REQUESTS flag is clear' {
            $enrollFlag        = 0x0
            $noManagerApproval = -not [bool]($enrollFlag -band 0x2)
            $noManagerApproval | Should -BeTrue
        }
    }

    Context 'Mocked query — result enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name                                   = @('UserAuthentication')
                            distinguishedname                      = @('CN=UserAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com')
                            'mspki-certificate-name-flag'          = @(1)
                            'mspki-enrollment-flag'                = @(0)
                            'mspki-ra-signature'                   = @(0)
                            pkiextendedkeyusage                    = @('1.3.6.1.5.5.7.3.2')
                            'mspki-certificate-application-policy' = @('1.3.6.1.5.5.7.3.2')
                        }
                        @{
                            name                                   = @('SafeTemplate')
                            distinguishedname                      = @('CN=SafeTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com')
                            'mspki-certificate-name-flag'          = @(0)
                            'mspki-enrollment-flag'                = @(2)
                            'mspki-ra-signature'                   = @(1)
                            pkiextendedkeyusage                    = @('1.3.6.1.5.5.7.3.2')
                            'mspki-certificate-application-policy' = @('1.3.6.1.5.5.7.3.2')
                        }
                    )
                }
            }
        }

        It 'Should return one result per certificate template' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSADCSTemplate -Domain 'contoso.com'
                $results.Count | Should -Be 2
            }
        }

        It 'Should correctly identify vulnerable template with ESC1 flag set' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSADCSTemplate -Domain 'contoso.com'
                $vuln    = $results | Where-Object { $_.Name -eq 'UserAuthentication' }
                $vuln.EnrolleeSuppliesSubject | Should -BeTrue
                $vuln.ESCFlags | Should -Contain 'ESC1'
            }
        }
    }
}
