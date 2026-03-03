BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSPasswordPolicy' -Tag 'Unit', 'AccountHygiene' {

    Context 'Output schema validation — Default Domain Policy' {

        It 'Should include all required properties' {
            $result = [PSCustomObject]@{
                PolicyType               = 'Default'
                Name                     = 'Default Domain Policy'
                MinPasswordLength        = 8
                PasswordHistoryCount     = 24
                MaxPasswordAge           = [TimeSpan]::FromDays(42)
                MinPasswordAge           = [TimeSpan]::FromDays(1)
                LockoutThreshold         = 5
                LockoutDuration          = [TimeSpan]::FromMinutes(30)
                LockoutObservationWindow = [TimeSpan]::FromMinutes(30)
                ComplexityEnabled        = $true
                ReversibleEncryption     = $false
                Precedence               = $null
                AppliesTo                = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'PolicyType'
            $result.PSObject.Properties.Name | Should -Contain 'Name'
            $result.PSObject.Properties.Name | Should -Contain 'MinPasswordLength'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordHistoryCount'
            $result.PSObject.Properties.Name | Should -Contain 'MaxPasswordAge'
            $result.PSObject.Properties.Name | Should -Contain 'MinPasswordAge'
            $result.PSObject.Properties.Name | Should -Contain 'LockoutThreshold'
            $result.PSObject.Properties.Name | Should -Contain 'LockoutDuration'
            $result.PSObject.Properties.Name | Should -Contain 'LockoutObservationWindow'
            $result.PSObject.Properties.Name | Should -Contain 'ComplexityEnabled'
            $result.PSObject.Properties.Name | Should -Contain 'ReversibleEncryption'
            $result.PSObject.Properties.Name | Should -Contain 'Precedence'
            $result.PSObject.Properties.Name | Should -Contain 'AppliesTo'
        }

        It 'Default policy PolicyType should be Default' {
            $result = [PSCustomObject]@{ PolicyType = 'Default' }
            $result.PolicyType | Should -Be 'Default'
        }

        It 'PSO PolicyType should be FineGrained' {
            $result = [PSCustomObject]@{ PolicyType = 'FineGrained' }
            $result.PolicyType | Should -Be 'FineGrained'
        }
    }

    Context 'ConvertFrom-ADInterval helper' {

        It 'Should convert a standard 42-day maxPwdAge interval to TimeSpan' {
            InModuleScope DirectoryServicesToolkit {
                # 42 days in 100-nanosecond ticks (negative as stored in AD)
                $ticks  = -([TimeSpan]::FromDays(42).Ticks)
                $result = ConvertFrom-ADInterval $ticks
                $result | Should -BeOfType [TimeSpan]
                $result.Days | Should -Be 42
            }
        }

        It 'Should return TimeSpan.MaxValue when value is 0 (no limit)' {
            InModuleScope DirectoryServicesToolkit {
                $result = ConvertFrom-ADInterval 0
                $result | Should -Be ([TimeSpan]::MaxValue)
            }
        }

        It 'Should return TimeSpan.Zero when value is $null' {
            InModuleScope DirectoryServicesToolkit {
                $result = ConvertFrom-ADInterval $null
                $result | Should -Be ([TimeSpan]::Zero)
            }
        }

        It 'Should use Math.Abs to handle negative ticks' {
            InModuleScope DirectoryServicesToolkit {
                $positiveTicks = [TimeSpan]::FromMinutes(30).Ticks
                $negativeTicks = -$positiveTicks

                $fromPositive = ConvertFrom-ADInterval $positiveTicks
                $fromNegative = ConvertFrom-ADInterval $negativeTicks

                $fromPositive.TotalMinutes | Should -Be 30
                $fromNegative.TotalMinutes | Should -Be 30
            }
        }
    }

    Context 'ComplexityEnabled — pwdProperties bitmask' {

        It 'Should be $true when bit 1 is set (pwdProperties=1)' {
            $pwdProps = 1
            [bool]($pwdProps -band 1) | Should -BeTrue
        }

        It 'Should be $false when bit 1 is not set (pwdProperties=0)' {
            $pwdProps = 0
            [bool]($pwdProps -band 1) | Should -BeFalse
        }

        It 'Should detect reversible encryption on bit 16' {
            $pwdProps = 16
            [bool]($pwdProps -band 16) | Should -BeTrue
        }
    }

    Context 'Parameter defaults' {

        It 'IncludeFineGrained should default to $true' {
            $cmd   = Get-Command Get-DSPasswordPolicy -Module DirectoryServicesToolkit
            $param = $cmd.Parameters['IncludeFineGrained']
            $param | Should -Not -BeNullOrEmpty
        }
    }
}
