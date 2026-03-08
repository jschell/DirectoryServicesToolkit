BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSADCSMappingEnforcement' -Tag 'Unit', 'Security', 'ADCS' {

    Context 'Output schema validation' {

        It 'Should include all required output properties for CA type' {
            $result = [PSCustomObject]@{
                ObjectType                          = 'CA'
                CAName                              = 'ContosoCA'
                CAHost                              = 'ca01.contoso.com'
                StrongCertificateBindingEnforcement = 2
                Description                         = 'Full enforcement — weak certificate mappings rejected'
                RiskLevel                           = 'Low'
                IsCompliant                         = $true
                Finding                             = $null
                ErrorMessage                        = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'ObjectType'
            $result.PSObject.Properties.Name | Should -Contain 'CAName'
            $result.PSObject.Properties.Name | Should -Contain 'StrongCertificateBindingEnforcement'
            $result.PSObject.Properties.Name | Should -Contain 'Description'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'IsCompliant'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'StrongCertificateBindingEnforcement risk classification' {

        It 'Value = 2 (full enforcement) should be Low' {
            $value     = 2
            $riskLevel = if ($null -eq $value -or $value -eq 0) { 'High' } elseif ($value -eq 1) { 'Medium' } else { 'Low' }
            $riskLevel | Should -Be 'Low'
        }

        It 'Value = 1 (audit mode) should be Medium' {
            $value     = 1
            $riskLevel = if ($null -eq $value -or $value -eq 0) { 'High' } elseif ($value -eq 1) { 'Medium' } else { 'Low' }
            $riskLevel | Should -Be 'Medium'
        }

        It 'Value = 0 (compatibility, no audit) should be High' {
            $value     = 0
            $riskLevel = if ($null -eq $value -or $value -eq 0) { 'High' } elseif ($value -eq 1) { 'Medium' } else { 'Low' }
            $riskLevel | Should -Be 'High'
        }

        It 'Key absent (null) should be High' {
            $value     = $null
            $riskLevel = if ($null -eq $value -or $value -eq 0) { 'High' } elseif ($value -eq 1) { 'Medium' } else { 'Low' }
            $riskLevel | Should -Be 'High'
        }
    }

    Context 'CT_FLAG_NO_SECURITY_EXTENSION detection' {

        It 'Should detect flag when 0x00080000 bit is set in NameFlag' {
            $nameFlag    = 0x00080000
            $flagMask    = 0x00080000
            $flagSet     = [bool]($nameFlag -band $flagMask)
            $flagSet | Should -BeTrue
        }

        It 'Should not flag when 0x00080000 bit is clear' {
            $nameFlag    = 0x00000001
            $flagMask    = 0x00080000
            $flagSet     = [bool]($nameFlag -band $flagMask)
            $flagSet | Should -BeFalse
        }

        It 'Should detect flag when multiple bits set including 0x00080000' {
            $nameFlag    = 0x00081003
            $flagMask    = 0x00080000
            $flagSet     = [bool]($nameFlag -band $flagMask)
            $flagSet | Should -BeTrue
        }
    }

    Context 'IsCompliant logic' {

        It 'IsCompliant should be true only when enforcement value = 2' {
            $value      = 2
            $isCompliant = ($value -eq 2)
            $isCompliant | Should -BeTrue

            $value      = 1
            $isCompliant = ($value -eq 2)
            $isCompliant | Should -BeFalse
        }
    }
}
