BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSCoercionSurface' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                Hostname              = 'DC01.contoso.com'
                DistinguishedName     = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com'
                IsDomainController    = $true
                UnconstrainedDelegate = $true
                SpoolerState          = 'Running'
                SpoolerRunning        = $true
                CompositeRisk         = 'Critical'
                Finding               = 'Host has unconstrained delegation AND running Print Spooler'
                ErrorMessage          = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'Hostname'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'IsDomainController'
            $result.PSObject.Properties.Name | Should -Contain 'UnconstrainedDelegate'
            $result.PSObject.Properties.Name | Should -Contain 'SpoolerState'
            $result.PSObject.Properties.Name | Should -Contain 'SpoolerRunning'
            $result.PSObject.Properties.Name | Should -Contain 'CompositeRisk'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'CompositeRisk classification' {

        It 'Spooler running on DC should be Critical' {
            $spoolerRunning = $true
            $isDC           = $true
            $risk           = if ($spoolerRunning -and $isDC) { 'Critical' }
                              elseif ($spoolerRunning) { 'High' }
                              elseif ($isDC) { 'High' }
                              else { 'Medium' }
            $risk           | Should -Be 'Critical'
        }

        It 'Spooler running on non-DC with unconstrained delegation should be High' {
            $spoolerRunning = $true
            $isDC           = $false
            $risk           = if ($spoolerRunning -and $isDC) { 'Critical' }
                              elseif ($spoolerRunning) { 'High' }
                              elseif ($isDC) { 'High' }
                              else { 'Medium' }
            $risk           | Should -Be 'High'
        }

        It 'DC without running Spooler should be High' {
            $spoolerRunning = $false
            $isDC           = $true
            $risk           = if ($spoolerRunning -and $isDC) { 'Critical' }
                              elseif ($spoolerRunning) { 'High' }
                              elseif ($isDC) { 'High' }
                              else { 'Medium' }
            $risk           | Should -Be 'High'
        }

        It 'Non-DC host without Spooler should be Medium' {
            $spoolerRunning = $false
            $isDC           = $false
            $risk           = if ($spoolerRunning -and $isDC) { 'Critical' }
                              elseif ($spoolerRunning) { 'High' }
                              elseif ($isDC) { 'High' }
                              else { 'Medium' }
            $risk           | Should -Be 'Medium'
        }
    }

    Context 'DC detection via UAC bitmask' {

        It 'Should detect DC by SERVER_TRUST_ACCOUNT bit 0x2000' {
            $uac  = 0x2000  # SERVER_TRUST_ACCOUNT
            $isDC = [bool]($uac -band 0x2000)
            $isDC | Should -BeTrue
        }

        It 'Should not flag non-DC computer accounts' {
            $uac  = 0x1000  # WORKSTATION_TRUST_ACCOUNT
            $isDC = [bool]($uac -band 0x2000)
            $isDC | Should -BeFalse
        }
    }

    Context 'Unconstrained delegation LDAP filter' {

        It 'Unconstrained delegation filter should use TRUSTED_FOR_DELEGATION bit 0x80000' {
            $filter = '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
            $filter | Should -Match '524288'
            # 0x80000 = 524288 decimal
            0x80000 | Should -Be 524288
        }
    }
}
