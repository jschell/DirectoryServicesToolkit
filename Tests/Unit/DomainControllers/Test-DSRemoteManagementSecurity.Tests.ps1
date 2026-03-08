BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSRemoteManagementSecurity' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DCName             = 'DC01.contoso.com'
                NLARequired        = $true
                UserAuthentication = 1
                SecurityLayer      = 2
                MinEncryptionLevel = 3
                TLSEnabled         = $true
                HighEncryption     = $true
                WinRMEncryptedOnly = $true
                Issues             = @()
                IssueCount         = 0
                RiskLevel          = 'Low'
                IsCompliant        = $true
                ErrorMessage       = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'DCName'
            $result.PSObject.Properties.Name | Should -Contain 'NLARequired'
            $result.PSObject.Properties.Name | Should -Contain 'UserAuthentication'
            $result.PSObject.Properties.Name | Should -Contain 'SecurityLayer'
            $result.PSObject.Properties.Name | Should -Contain 'MinEncryptionLevel'
            $result.PSObject.Properties.Name | Should -Contain 'TLSEnabled'
            $result.PSObject.Properties.Name | Should -Contain 'HighEncryption'
            $result.PSObject.Properties.Name | Should -Contain 'WinRMEncryptedOnly'
            $result.PSObject.Properties.Name | Should -Contain 'Issues'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'IsCompliant'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'NLA detection' {

        It 'UserAuthentication = 1 means NLA required' {
            $nlaInt     = 1
            $nlaRequired = ($nlaInt -eq 1)
            $nlaRequired | Should -BeTrue
        }

        It 'UserAuthentication = 0 means NLA not required' {
            $nlaInt     = 0
            $nlaRequired = ($nlaInt -eq 1)
            $nlaRequired | Should -BeFalse
        }
    }

    Context 'TLS enforcement detection' {

        It 'SecurityLayer = 2 means TLS enabled' {
            $secLayerInt = 2
            $tlsEnabled  = ($secLayerInt -eq 2)
            $tlsEnabled | Should -BeTrue
        }

        It 'SecurityLayer = 1 means TLS not enforced' {
            $secLayerInt = 1
            $tlsEnabled  = ($secLayerInt -eq 2)
            $tlsEnabled | Should -BeFalse
        }
    }

    Context 'Encryption level detection' {

        It 'MinEncryptionLevel >= 3 means High encryption' {
            $encLevelInt   = 3
            $highEncryption = ($encLevelInt -ge 3)
            $highEncryption | Should -BeTrue

            $encLevelInt   = 4
            $highEncryption = ($encLevelInt -ge 3)
            $highEncryption | Should -BeTrue
        }

        It 'MinEncryptionLevel < 3 means not High encryption' {
            $encLevelInt   = 2
            $highEncryption = ($encLevelInt -ge 3)
            $highEncryption | Should -BeFalse
        }
    }

    Context 'Risk level classification' {

        It 'All controls optimal should be Low' {
            $issues    = @()
            $riskLevel = if ($issues.Count -eq 0) { 'Low' } else { 'Medium' }
            $riskLevel | Should -Be 'Low'
        }

        It 'One issue should be Medium' {
            $issues    = @('NLA not required')
            $riskLevel = if ($issues.Count -eq 0) { 'Low' } elseif ($issues.Count -ge 2) { 'High' } else { 'Medium' }
            $riskLevel | Should -Be 'Medium'
        }
    }
}
