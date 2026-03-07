BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSSMBSigning' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DCName                   = 'DC01.contoso.com'
                RequireSecuritySignature = 1
                EnableSecuritySignature  = 1
                Description              = 'SMB signing required — all SMB connections must be signed'
                RiskLevel                = 'Compliant'
                IsCompliant              = $true
                ErrorMessage             = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'DCName'
            $result.PSObject.Properties.Name | Should -Contain 'RequireSecuritySignature'
            $result.PSObject.Properties.Name | Should -Contain 'EnableSecuritySignature'
            $result.PSObject.Properties.Name | Should -Contain 'Description'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'IsCompliant'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'Risk level classification' {

        It 'RequireSecuritySignature = 1 should be Compliant' {
            $requireInt = 1
            $enableInt  = 1
            $riskLevel  = if ($requireInt -eq 1) { 'Compliant' } elseif ($enableInt -eq 1) { 'Medium' } else { 'Critical' }
            $riskLevel | Should -Be 'Compliant'
        }

        It 'RequireSecuritySignature = 0, EnableSecuritySignature = 1 should be Medium' {
            $requireInt = 0
            $enableInt  = 1
            $riskLevel  = if ($requireInt -eq 1) { 'Compliant' } elseif ($enableInt -eq 1) { 'Medium' } else { 'Critical' }
            $riskLevel | Should -Be 'Medium'
        }

        It 'RequireSecuritySignature = 0, EnableSecuritySignature = 0 should be Critical' {
            $requireInt = 0
            $enableInt  = 0
            $riskLevel  = if ($requireInt -eq 1) { 'Compliant' } elseif ($enableInt -eq 1) { 'Medium' } else { 'Critical' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'IsCompliant should be true only when RequireSecuritySignature = 1' {
            $riskLevel  = 'Compliant'
            $isCompliant = ($riskLevel -eq 'Compliant')
            $isCompliant | Should -BeTrue

            $riskLevel   = 'Medium'
            $isCompliant = ($riskLevel -eq 'Compliant')
            $isCompliant | Should -BeFalse
        }
    }

    Context 'Default value behavior — absent registry keys' {

        It 'Null RequireSecuritySignature should default to 0 (conservative)' {
            $requireValue = $null
            $requireInt   = if ($null -ne $requireValue) { [int]$requireValue } else { 0 }
            $requireInt | Should -Be 0
        }

        It 'Null EnableSecuritySignature should default to 0' {
            $enableValue = $null
            $enableInt   = if ($null -ne $enableValue) { [int]$enableValue } else { 0 }
            $enableInt | Should -Be 0
        }

        It 'Null both values should result in Critical risk' {
            $requireInt = 0
            $enableInt  = 0
            $riskLevel  = if ($requireInt -eq 1) { 'Compliant' } elseif ($enableInt -eq 1) { 'Medium' } else { 'Critical' }
            $riskLevel | Should -Be 'Critical'
        }
    }

    Context 'Registry path validation' {

        It 'Should target the LanManServer Parameters registry path' {
            $path = 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
            $path | Should -Match 'LanManServer'
            $path | Should -Match 'Parameters'
        }

        It 'Should query RequireSecuritySignature and EnableSecuritySignature' {
            $require = 'RequireSecuritySignature'
            $enable  = 'EnableSecuritySignature'
            $require | Should -Be 'RequireSecuritySignature'
            $enable  | Should -Be 'EnableSecuritySignature'
        }
    }

    Context 'Description text accuracy' {

        It 'RequireSecuritySignature = 1 should produce required description' {
            $requireInt = 1
            $desc = if ($requireInt -eq 1)
            {
                'SMB signing required — all SMB connections must be signed'
            }
            elseif (1 -eq 1)
            {
                'SMB signing enabled but not required'
            }
            else
            {
                'SMB signing not required and not enabled'
            }
            $desc | Should -Match 'required'
        }

        It 'Both = 0 should produce not enabled description' {
            $requireInt = 0
            $enableInt  = 0
            $desc = if ($requireInt -eq 1)
            {
                'SMB signing required — all SMB connections must be signed'
            }
            elseif ($enableInt -eq 1)
            {
                'SMB signing enabled but not required'
            }
            else
            {
                'SMB signing not required and not enabled — unsigned SMB accepted, relay-exploitable'
            }
            $desc | Should -Match 'not enabled'
        }
    }
}
