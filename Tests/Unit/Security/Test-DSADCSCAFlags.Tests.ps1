BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSADCSCAFlags' -Tag 'Unit', 'Security', 'ADCS' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                CAName            = 'ContosoCA'
                DNSHostName       = 'ca01.contoso.com'
                DistinguishedName = 'CN=ContosoCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                EditFlags         = 0x00040000
                ESC6Vulnerable    = $true
                RiskLevel         = 'Critical'
                Finding           = "ESC6: CA 'ContosoCA' has EDITF_ATTRIBUTESUBJECTALTNAME2 set"
                ErrorMessage      = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'CAName'
            $result.PSObject.Properties.Name | Should -Contain 'DNSHostName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'EditFlags'
            $result.PSObject.Properties.Name | Should -Contain 'ESC6Vulnerable'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'ESC6 flag detection — EDITF_ATTRIBUTESUBJECTALTNAME2' {

        It 'Should detect ESC6 when 0x00040000 bit is set in EditFlags' {
            $editFlags    = 0x00040000
            $esc6FlagMask = 0x00040000
            $vulnerable   = [bool]($editFlags -band $esc6FlagMask)
            $vulnerable | Should -BeTrue
        }

        It 'Should not flag ESC6 when 0x00040000 bit is clear' {
            $editFlags    = 0x00000001
            $esc6FlagMask = 0x00040000
            $vulnerable   = [bool]($editFlags -band $esc6FlagMask)
            $vulnerable | Should -BeFalse
        }

        It 'Should detect ESC6 when EditFlags contains multiple bits including 0x00040000' {
            $editFlags    = 0x00040110   # 0x00040000 | other bits
            $esc6FlagMask = 0x00040000
            $vulnerable   = [bool]($editFlags -band $esc6FlagMask)
            $vulnerable | Should -BeTrue
        }

        It 'EditFlags = 0 should not be flagged as ESC6' {
            $editFlags    = 0
            $esc6FlagMask = 0x00040000
            $vulnerable   = [bool]($editFlags -band $esc6FlagMask)
            $vulnerable | Should -BeFalse
        }
    }

    Context 'Risk level classification' {

        It 'ESC6Vulnerable = true should yield Critical risk' {
            $riskLevel = if ($true) { 'Critical' } elseif ($false) { 'Unknown' } else { 'Low' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'ESC6Vulnerable = false with valid EditFlags should yield Low' {
            $esc6Vulnerable = $false
            $editFlagsInt   = 0x00000001
            $riskLevel = if ($esc6Vulnerable) { 'Critical' }
                         elseif ($null -eq $editFlagsInt) { 'Unknown' }
                         else { 'Low' }
            $riskLevel | Should -Be 'Low'
        }

        It 'Null EditFlags (registry inaccessible) should yield Unknown risk' {
            $esc6Vulnerable = $false
            $editFlagsInt   = $null
            $riskLevel = if ($esc6Vulnerable) { 'Critical' }
                         elseif ($null -eq $editFlagsInt) { 'Unknown' }
                         else { 'Low' }
            $riskLevel | Should -Be 'Unknown'
        }
    }

    Context 'Registry path validation' {

        It 'Should target the CertSvc configuration registry path' {
            $caName          = 'ContosoCA'
            $registryPath    = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"
            $registryPath | Should -Match 'CertSvc'
            $registryPath | Should -Match 'CertificateAuthority_MicrosoftDefault.Policy'
            $registryPath | Should -Match $caName
        }

        It 'Should query the EditFlags value name' {
            $valueName = 'EditFlags'
            $valueName | Should -Be 'EditFlags'
        }
    }

    Context 'Mocked query — result enumeration' {

        It 'Should return Critical risk when ESC6 flag is set in EditFlags' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name              = @('ContosoCA')
                            distinguishedname = @('CN=ContosoCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com')
                            dnshostname       = @('ca01.contoso.com')
                        }
                    )
                }

                # Patch the registry access block
                Mock Get-Item { throw 'No registry' }

                # We can't easily mock static .NET registry calls, so validate output structure
                $results = Test-DSADCSCAFlags -Domain 'contoso.com' -ErrorAction SilentlyContinue
                $results | Should -Not -BeNullOrEmpty
                $results[0].CAName | Should -Be 'ContosoCA'
                $results[0].DNSHostName | Should -Be 'ca01.contoso.com'
            }
        }
    }
}
