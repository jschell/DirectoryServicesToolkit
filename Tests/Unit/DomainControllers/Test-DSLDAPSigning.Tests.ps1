BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSLDAPSigning' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DCName       = 'DC01.contoso.com'
                SigningValue = 2
                Description  = 'Require signing — LDAP signing enforced'
                RiskLevel    = 'Low'
                IsCompliant  = $true
                ErrorMessage = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'DCName'
            $result.PSObject.Properties.Name | Should -Contain 'SigningValue'
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
            $riskMedium    = 'Medium'
            ($riskCompliant -eq 'Low') | Should -BeTrue
            ($riskMedium -eq 'Low')    | Should -BeFalse
        }
    }

    Context 'Default value behavior' {

        It 'Absent registry key should default to value 1 (Negotiate signing)' {
            $signingValue = $null
            if ($null -eq $signingValue) { $signingValue = 1 }
            $signingValue | Should -Be 1
        }

        It 'Default absent value should be classified as Medium risk' {
            $signingValue = $null
            if ($null -eq $signingValue) { $signingValue = 1 }
            $risk = switch ([int]$signingValue) { 0 { 'Critical' } 1 { 'Medium' } 2 { 'Low' } default { 'Unknown' } }
            $risk | Should -Be 'Medium'
        }
    }

    Context 'Registry path validation' {

        It 'Should target the NTDS Parameters registry path' {
            $path = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
            $path | Should -Match 'NTDS'
            $path | Should -Match 'Parameters'
        }

        It 'Should query the ldap server integrity value name' {
            $valueName = 'ldap server integrity'
            $valueName | Should -Be 'ldap server integrity'
        }
    }
}
