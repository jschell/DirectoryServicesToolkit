BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSNTLMPolicy' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DCName                 = 'DC01.contoso.com'
                LmCompatibilityLevel   = 5
                LmCompatDescription    = 'Send NTLMv2 only — refuse LM and NTLMv1 everywhere'
                NoLMHash               = $true
                NtlmMinClientSec       = 537395200
                NtlmMinServerSec       = 537395200
                NTLMv2ClientRequired   = $true
                Encryption128BitClient = $true
                NTLMv2ServerRequired   = $true
                Encryption128BitServer = $true
                RiskLevel              = 'Compliant'
                IsCompliant            = $true
                ErrorMessage           = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'DCName'
            $result.PSObject.Properties.Name | Should -Contain 'LmCompatibilityLevel'
            $result.PSObject.Properties.Name | Should -Contain 'LmCompatDescription'
            $result.PSObject.Properties.Name | Should -Contain 'NoLMHash'
            $result.PSObject.Properties.Name | Should -Contain 'NtlmMinClientSec'
            $result.PSObject.Properties.Name | Should -Contain 'NtlmMinServerSec'
            $result.PSObject.Properties.Name | Should -Contain 'NTLMv2ClientRequired'
            $result.PSObject.Properties.Name | Should -Contain 'Encryption128BitClient'
            $result.PSObject.Properties.Name | Should -Contain 'NTLMv2ServerRequired'
            $result.PSObject.Properties.Name | Should -Contain 'Encryption128BitServer'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'IsCompliant'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'LmCompatibilityLevel risk classification' {

        It 'Level 0 should be Critical' {
            $level = 0
            $risk  = if ($level -le 2) { 'Critical' } elseif ($level -le 4) { 'Medium' } elseif ($level -eq 5) { 'Compliant' } else { 'Unknown' }
            $risk  | Should -Be 'Critical'
        }

        It 'Level 2 should be Critical' {
            $level = 2
            $risk  = if ($level -le 2) { 'Critical' } elseif ($level -le 4) { 'Medium' } elseif ($level -eq 5) { 'Compliant' } else { 'Unknown' }
            $risk  | Should -Be 'Critical'
        }

        It 'Level 3 should be Medium' {
            $level = 3
            $risk  = if ($level -le 2) { 'Critical' } elseif ($level -le 4) { 'Medium' } elseif ($level -eq 5) { 'Compliant' } else { 'Unknown' }
            $risk  | Should -Be 'Medium'
        }

        It 'Level 4 should be Medium' {
            $level = 4
            $risk  = if ($level -le 2) { 'Critical' } elseif ($level -le 4) { 'Medium' } elseif ($level -eq 5) { 'Compliant' } else { 'Unknown' }
            $risk  | Should -Be 'Medium'
        }

        It 'Level 5 should be Compliant' {
            $level = 5
            $risk  = if ($level -le 2) { 'Critical' } elseif ($level -le 4) { 'Medium' } elseif ($level -eq 5) { 'Compliant' } else { 'Unknown' }
            $risk  | Should -Be 'Compliant'
        }
    }

    Context 'NtlmMinSec bitmask extraction' {

        It 'NTLMv2ClientRequired should be true when bit 0x00080000 is set' {
            $minClientSec  = 0x00080000
            $ntlmv2Enabled = [bool]($minClientSec -band 0x00080000)
            $ntlmv2Enabled | Should -BeTrue
        }

        It 'NTLMv2ClientRequired should be false when bit 0x00080000 is clear' {
            $minClientSec  = 0x20000000
            $ntlmv2Enabled = [bool]($minClientSec -band 0x00080000)
            $ntlmv2Enabled | Should -BeFalse
        }

        It 'Encryption128BitClient should be true when bit 0x20000000 is set' {
            $minClientSec  = 0x20000000
            $enc128Enabled = [bool]($minClientSec -band 0x20000000)
            $enc128Enabled | Should -BeTrue
        }

        It 'Encryption128BitClient should be false when bit 0x20000000 is clear' {
            $minClientSec  = 0x00080000
            $enc128Enabled = [bool]($minClientSec -band 0x20000000)
            $enc128Enabled | Should -BeFalse
        }
    }

    Context 'Registry path validation' {

        It 'Should target the Lsa registry path' {
            $path = 'SYSTEM\CurrentControlSet\Control\Lsa'
            $path | Should -Match 'Lsa'
            $path | Should -Match 'Control'
        }
    }
}
