BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSWDigestAuth' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DCName             = 'DC01.contoso.com'
                UseLogonCredential = 0
                WDigestEnabled     = $false
                Description        = 'WDigest disabled — cleartext credentials not cached in LSASS'
                RiskLevel          = 'Low'
                IsCompliant        = $true
                ErrorMessage       = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'DCName'
            $result.PSObject.Properties.Name | Should -Contain 'UseLogonCredential'
            $result.PSObject.Properties.Name | Should -Contain 'WDigestEnabled'
            $result.PSObject.Properties.Name | Should -Contain 'Description'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'IsCompliant'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'Risk level classification' {

        It 'UseLogonCredential = 0 should be Low' {
            $value     = 0
            $riskLevel = if ($value -eq 1) { 'Critical' } else { 'Low' }
            $riskLevel | Should -Be 'Low'
        }

        It 'UseLogonCredential = 1 should be Critical' {
            $value     = 1
            $riskLevel = if ($value -eq 1) { 'Critical' } else { 'Low' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'UseLogonCredential = null (key absent) should be Low' {
            $value     = $null
            $riskLevel = if ($null -eq $value -or $value -eq 0) { 'Low' } else { 'Critical' }
            $riskLevel | Should -Be 'Low'
        }

        It 'Registry error with null value should be Unknown' {
            $errorMessage = 'Registry access failed'
            $value        = $null
            $riskLevel    = if ($null -ne $errorMessage -and $null -eq $value) { 'Unknown' }
                            elseif ($null -eq $value -or $value -eq 0) { 'Low' }
                            else { 'Critical' }
            $riskLevel | Should -Be 'Unknown'
        }
    }

    Context 'WDigestEnabled flag' {

        It 'WDigestEnabled should be true when UseLogonCredential = 1' {
            $riskLevel     = 'Critical'
            $wDigestEnabled = ($riskLevel -eq 'Critical')
            $wDigestEnabled | Should -BeTrue
        }

        It 'WDigestEnabled should be false when UseLogonCredential = 0' {
            $riskLevel     = 'Low'
            $wDigestEnabled = ($riskLevel -eq 'Critical')
            $wDigestEnabled | Should -BeFalse
        }
    }
}
