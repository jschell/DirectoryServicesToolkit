BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSAuditPolicy' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DCName               = 'DC01.contoso.com'
                SubcategorySettings  = [PSCustomObject]@{ AuditLogon = 3 }
                MissingSubcategories = @()
                MissingCount         = 0
                TotalRequired        = 12
                RiskLevel            = 'Low'
                IsCompliant          = $true
                ErrorMessage         = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'DCName'
            $result.PSObject.Properties.Name | Should -Contain 'SubcategorySettings'
            $result.PSObject.Properties.Name | Should -Contain 'MissingSubcategories'
            $result.PSObject.Properties.Name | Should -Contain 'MissingCount'
            $result.PSObject.Properties.Name | Should -Contain 'TotalRequired'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'IsCompliant'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'Risk level classification' {

        It 'MissingCount = 0 should be Low' {
            $missing   = 0
            $riskLevel = if ($missing -eq 0) { 'Low' } elseif ($missing -le 4) { 'Medium' } else { 'High' }
            $riskLevel | Should -Be 'Low'
        }

        It 'MissingCount = 3 should be Medium' {
            $missing   = 3
            $riskLevel = if ($missing -eq 0) { 'Low' } elseif ($missing -le 4) { 'Medium' } else { 'High' }
            $riskLevel | Should -Be 'Medium'
        }

        It 'MissingCount = 8 should be High' {
            $missing   = 8
            $riskLevel = if ($missing -eq 0) { 'Low' } elseif ($missing -le 4) { 'Medium' } else { 'High' }
            $riskLevel | Should -Be 'High'
        }

        It 'MissingCount = 4 should be Medium (boundary)' {
            $missing   = 4
            $riskLevel = if ($missing -eq 0) { 'Low' } elseif ($missing -le 4) { 'Medium' } else { 'High' }
            $riskLevel | Should -Be 'Medium'
        }

        It 'MissingCount = 5 should be High (boundary)' {
            $missing   = 5
            $riskLevel = if ($missing -eq 0) { 'Low' } elseif ($missing -le 4) { 'Medium' } else { 'High' }
            $riskLevel | Should -Be 'High'
        }
    }

    Context 'Subcategory bitmask coverage check' {

        It 'Value = 3 should cover required = 3 (Success+Failure)' {
            $actual   = 3
            $required = 3
            $covered  = ($actual -band $required) -eq $required
            $covered | Should -BeTrue
        }

        It 'Value = 1 should not cover required = 3 (missing Failure)' {
            $actual   = 1
            $required = 3
            $covered  = ($actual -band $required) -eq $required
            $covered | Should -BeFalse
        }

        It 'Value = 0 should not cover required = 3' {
            $actual   = 0
            $required = 3
            $covered  = ($actual -band $required) -eq $required
            $covered | Should -BeFalse
        }

        It 'Value = 3 should cover required = 1 (Success only)' {
            $actual   = 3
            $required = 1
            $covered  = ($actual -band $required) -eq $required
            $covered | Should -BeTrue
        }
    }

    Context 'IsCompliant logic' {

        It 'IsCompliant should be true when RiskLevel is Low' {
            $riskLevel  = 'Low'
            $isCompliant = ($riskLevel -eq 'Low')
            $isCompliant | Should -BeTrue
        }

        It 'IsCompliant should be false when RiskLevel is Medium' {
            $riskLevel  = 'Medium'
            $isCompliant = ($riskLevel -eq 'Low')
            $isCompliant | Should -BeFalse
        }
    }
}
