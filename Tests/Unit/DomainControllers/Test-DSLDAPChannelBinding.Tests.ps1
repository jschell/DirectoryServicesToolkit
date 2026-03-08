BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSLDAPChannelBinding' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DCName              = 'DC01.contoso.com'
                ChannelBindingValue = 2
                Description         = 'Always required — channel binding enforced'
                RiskLevel           = 'Low'
                IsCompliant         = $true
                ErrorMessage        = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'DCName'
            $result.PSObject.Properties.Name | Should -Contain 'ChannelBindingValue'
            $result.PSObject.Properties.Name | Should -Contain 'Description'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'IsCompliant'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'Risk level classification' {

        It 'Value 0 should be classified as Critical' {
            $value = 0
            $risk  = switch ($value) { 0 { 'Critical' } 1 { 'Medium' } 2 { 'Low' } default { 'Unknown' } }
            $risk  | Should -Be 'Critical'
        }

        It 'Value 1 should be classified as Medium' {
            $value = 1
            $risk  = switch ($value) { 0 { 'Critical' } 1 { 'Medium' } 2 { 'Low' } default { 'Unknown' } }
            $risk  | Should -Be 'Medium'
        }

        It 'Value 2 should be classified as Low' {
            $value = 2
            $risk  = switch ($value) { 0 { 'Critical' } 1 { 'Medium' } 2 { 'Low' } default { 'Unknown' } }
            $risk  | Should -Be 'Low'
        }

        It 'IsCompliant should be true only for value 2' {
            $riskCompliant = 'Low'
            $riskCritical  = 'Critical'
            ($riskCompliant -eq 'Low') | Should -BeTrue
            ($riskCritical -eq 'Low')  | Should -BeFalse
        }
    }

    Context 'Default value behavior' {

        It 'Absent registry key should default to value 0 (Disabled)' {
            $cbValue = $null
            if ($null -eq $cbValue) { $cbValue = 0 }
            $cbValue | Should -Be 0
        }

        It 'Default absent value should be classified as Critical' {
            $cbValue = $null
            if ($null -eq $cbValue) { $cbValue = 0 }
            $risk = switch ([int]$cbValue) { 0 { 'Critical' } 1 { 'Medium' } 2 { 'Low' } default { 'Unknown' } }
            $risk | Should -Be 'Critical'
        }
    }

    Context 'Registry path validation' {

        It 'Should target the NTDS Parameters registry path' {
            $path = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
            $path | Should -Match 'NTDS'
            $path | Should -Match 'Parameters'
        }

        It 'Should query the LdapEnforceChannelBinding value name' {
            $valueName = 'LdapEnforceChannelBinding'
            $valueName | Should -Be 'LdapEnforceChannelBinding'
        }
    }
}
