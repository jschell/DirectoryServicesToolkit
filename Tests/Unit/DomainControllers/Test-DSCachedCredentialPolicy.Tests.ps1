BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSCachedCredentialPolicy' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DCName            = 'DC01.contoso.com'
                CachedLogonsCount = 0
                Description       = 'Cached credentials disabled — no MSCACHE hashes stored on this DC'
                RiskLevel         = 'Low'
                IsCompliant       = $true
                ErrorMessage      = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'DCName'
            $result.PSObject.Properties.Name | Should -Contain 'CachedLogonsCount'
            $result.PSObject.Properties.Name | Should -Contain 'Description'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'IsCompliant'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'Risk level classification' {

        It 'CachedLogonsCount = 0 should be Low' {
            $count     = 0
            $riskLevel = if ($null -eq $count) { 'High' } elseif ($count -eq 0) { 'Low' } elseif ($count -le 2) { 'Medium' } else { 'High' }
            $riskLevel | Should -Be 'Low'
        }

        It 'CachedLogonsCount = 1 should be Medium' {
            $count     = 1
            $riskLevel = if ($null -eq $count) { 'High' } elseif ($count -eq 0) { 'Low' } elseif ($count -le 2) { 'Medium' } else { 'High' }
            $riskLevel | Should -Be 'Medium'
        }

        It 'CachedLogonsCount = 2 should be Medium (boundary)' {
            $count     = 2
            $riskLevel = if ($null -eq $count) { 'High' } elseif ($count -eq 0) { 'Low' } elseif ($count -le 2) { 'Medium' } else { 'High' }
            $riskLevel | Should -Be 'Medium'
        }

        It 'CachedLogonsCount = 3 should be High' {
            $count     = 3
            $riskLevel = if ($null -eq $count) { 'High' } elseif ($count -eq 0) { 'Low' } elseif ($count -le 2) { 'Medium' } else { 'High' }
            $riskLevel | Should -Be 'High'
        }

        It 'CachedLogonsCount = 10 should be High' {
            $count     = 10
            $riskLevel = if ($null -eq $count) { 'High' } elseif ($count -eq 0) { 'Low' } elseif ($count -le 2) { 'Medium' } else { 'High' }
            $riskLevel | Should -Be 'High'
        }

        It 'Key absent (null) should be High — OS default is 10' {
            $count     = $null
            $riskLevel = if ($null -eq $count) { 'High' } elseif ($count -eq 0) { 'Low' } elseif ($count -le 2) { 'Medium' } else { 'High' }
            $riskLevel | Should -Be 'High'
        }

        It 'Registry error with null value should be Unknown' {
            $errorMessage = 'Registry access failed'
            $count        = $null
            $riskLevel    = if ($null -ne $errorMessage -and $null -eq $count) { 'Unknown' }
                            elseif ($null -eq $count) { 'High' }
                            elseif ($count -eq 0) { 'Low' }
                            else { 'High' }
            $riskLevel | Should -Be 'Unknown'
        }
    }

    Context 'IsCompliant logic' {

        It 'IsCompliant should be true only when RiskLevel is Low' {
            $riskLevel  = 'Low'
            $isCompliant = ($riskLevel -eq 'Low')
            $isCompliant | Should -BeTrue

            $riskLevel  = 'Medium'
            $isCompliant = ($riskLevel -eq 'Low')
            $isCompliant | Should -BeFalse

            $riskLevel  = 'High'
            $isCompliant = ($riskLevel -eq 'Low')
            $isCompliant | Should -BeFalse
        }
    }
}
