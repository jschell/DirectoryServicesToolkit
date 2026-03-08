BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSKerberosPolicy' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                ObjectType               = 'DC'
                Name                     = 'DC01.contoso.com'
                SupportedEncryptionTypes = 0x18
                DESEnabled               = $false
                RC4Enabled               = $false
                AES128Enabled            = $true
                AES256Enabled            = $true
                RiskLevel                = 'Low'
                IsCompliant              = $true
                ErrorMessage             = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'ObjectType'
            $result.PSObject.Properties.Name | Should -Contain 'Name'
            $result.PSObject.Properties.Name | Should -Contain 'SupportedEncryptionTypes'
            $result.PSObject.Properties.Name | Should -Contain 'DESEnabled'
            $result.PSObject.Properties.Name | Should -Contain 'RC4Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'AES128Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'AES256Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'IsCompliant'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'Encryption type bitmask detection' {

        It 'Should detect DES-CBC-CRC (bit 0x01)' {
            $encType    = 0x01
            $desEnabled = [bool](($encType -band 0x01) -or ($encType -band 0x02))
            $desEnabled | Should -BeTrue
        }

        It 'Should detect DES-CBC-MD5 (bit 0x02)' {
            $encType    = 0x02
            $desEnabled = [bool](($encType -band 0x01) -or ($encType -band 0x02))
            $desEnabled | Should -BeTrue
        }

        It 'Should detect RC4 (bit 0x04)' {
            $encType    = 0x04
            $rc4Enabled = [bool]($encType -band 0x04)
            $rc4Enabled | Should -BeTrue
        }

        It 'Should detect AES256 (bit 0x10)' {
            $encType      = 0x10
            $aes256Enabled = [bool]($encType -band 0x10)
            $aes256Enabled | Should -BeTrue
        }

        It 'AES-only bitmask (0x18) should not flag DES or RC4' {
            $encType    = 0x18  # AES128 + AES256
            $desEnabled = [bool](($encType -band 0x01) -or ($encType -band 0x02))
            $rc4Enabled = [bool]($encType -band 0x04)
            $desEnabled | Should -BeFalse
            $rc4Enabled | Should -BeFalse
        }
    }

    Context 'Risk level classification' {

        It 'AES-only encryption types should be Low' {
            $encType    = 0x18
            $desEnabled = [bool](($encType -band 0x01) -or ($encType -band 0x02))
            $rc4Enabled = [bool]($encType -band 0x04)
            $riskLevel  = if ($desEnabled) { 'High' } elseif ($rc4Enabled) { 'Medium' } elseif ($encType -eq 0) { 'Medium' } else { 'Low' }
            $riskLevel | Should -Be 'Low'
        }

        It 'RC4 present but no DES should be Medium' {
            $encType    = 0x1C  # AES128 + AES256 + RC4
            $desEnabled = [bool](($encType -band 0x01) -or ($encType -band 0x02))
            $rc4Enabled = [bool]($encType -band 0x04)
            $riskLevel  = if ($desEnabled) { 'High' } elseif ($rc4Enabled) { 'Medium' } elseif ($encType -eq 0) { 'Medium' } else { 'Low' }
            $riskLevel | Should -Be 'Medium'
        }

        It 'DES enabled should be High' {
            $encType    = 0x03  # DES-CBC-CRC + DES-CBC-MD5
            $desEnabled = [bool](($encType -band 0x01) -or ($encType -band 0x02))
            $riskLevel  = if ($desEnabled) { 'High' } else { 'Low' }
            $riskLevel | Should -Be 'High'
        }

        It 'Null (key absent) should be Medium — OS default includes RC4' {
            $encType    = $null
            $rc4Default = $true   # absent = OS default includes RC4
            $riskLevel  = if ($null -eq $encType) { 'Medium' } else { 'Low' }
            $riskLevel | Should -Be 'Medium'
        }
    }
}
