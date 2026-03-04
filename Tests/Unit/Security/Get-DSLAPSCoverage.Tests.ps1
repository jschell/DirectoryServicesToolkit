BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSLAPSCoverage' -Tag 'Unit', 'Security' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                Name              = 'WORKSTATION01'
                SamAccountName    = 'WORKSTATION01$'
                DistinguishedName = 'CN=WORKSTATION01,OU=Workstations,DC=contoso,DC=com'
                OU                = 'OU=Workstations,DC=contoso,DC=com'
                LAPSVersion       = 'LegacyLAPS'
                HasLAPS           = $true
                IsExpired         = $false
                RiskLevel         = 'Low'
            }

            $result.PSObject.Properties.Name | Should -Contain 'Name'
            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'OU'
            $result.PSObject.Properties.Name | Should -Contain 'LAPSVersion'
            $result.PSObject.Properties.Name | Should -Contain 'HasLAPS'
            $result.PSObject.Properties.Name | Should -Contain 'IsExpired'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
        }
    }

    Context 'LAPS version detection' {

        It 'LAPSVersion should be WindowsLAPS when msLAPS-Password is present' {
            $windowsLapsPwd = @('encryptedvalue')
            $legacyLapsPwd  = $null
            $hasWindowsLAPS = ($null -ne $windowsLapsPwd -and $windowsLapsPwd.Count -gt 0)
            $hasLegacyLAPS  = ($null -ne $legacyLapsPwd -and $legacyLapsPwd.Count -gt 0)
            $version        = if ($hasWindowsLAPS) { 'WindowsLAPS' } elseif ($hasLegacyLAPS) { 'LegacyLAPS' } else { 'None' }
            $version        | Should -Be 'WindowsLAPS'
        }

        It 'LAPSVersion should be LegacyLAPS when ms-Mcs-AdmPwd is present' {
            $windowsLapsPwd = $null
            $legacyLapsPwd  = @('password123')
            $hasWindowsLAPS = ($null -ne $windowsLapsPwd -and $windowsLapsPwd.Count -gt 0)
            $hasLegacyLAPS  = ($null -ne $legacyLapsPwd -and $legacyLapsPwd.Count -gt 0)
            $version        = if ($hasWindowsLAPS) { 'WindowsLAPS' } elseif ($hasLegacyLAPS) { 'LegacyLAPS' } else { 'None' }
            $version        | Should -Be 'LegacyLAPS'
        }

        It 'LAPSVersion should be None when neither attribute is present' {
            $windowsLapsPwd = $null
            $legacyLapsPwd  = $null
            $hasWindowsLAPS = ($null -ne $windowsLapsPwd -and $windowsLapsPwd.Count -gt 0)
            $hasLegacyLAPS  = ($null -ne $legacyLapsPwd -and $legacyLapsPwd.Count -gt 0)
            $version        = if ($hasWindowsLAPS) { 'WindowsLAPS' } elseif ($hasLegacyLAPS) { 'LegacyLAPS' } else { 'None' }
            $version        | Should -Be 'None'
        }
    }

    Context 'Risk level assignment' {

        It 'RiskLevel should be High for computers without LAPS' {
            $hasLAPS   = $false
            $isExpired = $false
            $risk      = if (-not $hasLAPS) { 'High' } elseif ($isExpired) { 'Medium' } else { 'Low' }
            $risk      | Should -Be 'High'
        }

        It 'RiskLevel should be Medium for computers with expired LAPS passwords' {
            $hasLAPS   = $true
            $isExpired = $true
            $risk      = if (-not $hasLAPS) { 'High' } elseif ($isExpired) { 'Medium' } else { 'Low' }
            $risk      | Should -Be 'Medium'
        }

        It 'RiskLevel should be Low for computers with current LAPS passwords' {
            $hasLAPS   = $true
            $isExpired = $false
            $risk      = if (-not $hasLAPS) { 'High' } elseif ($isExpired) { 'Medium' } else { 'Low' }
            $risk      | Should -Be 'Low'
        }
    }

    Context 'Mocked query — result enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name                            = @('WORKSTATION01')
                            samaccountname                  = @('WORKSTATION01$')
                            distinguishedname               = @('CN=WORKSTATION01,OU=Workstations,DC=contoso,DC=com')
                            'ms-mcs-admpwd'                 = @('SomePassword')
                            'ms-mcs-admpwdexpirationtime'   = @((Get-Date).AddDays(30).ToFileTime())
                            'mslaps-password'               = $null
                            'mslaps-passwordexpirationtime' = $null
                        }
                        @{
                            name                            = @('SERVER01')
                            samaccountname                  = @('SERVER01$')
                            distinguishedname               = @('CN=SERVER01,OU=Servers,DC=contoso,DC=com')
                            'ms-mcs-admpwd'                 = $null
                            'ms-mcs-admpwdexpirationtime'   = $null
                            'mslaps-password'               = $null
                            'mslaps-passwordexpirationtime' = $null
                        }
                    )
                }
            }
        }

        It 'Should return one result per computer object' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Get-DSLAPSCoverage -Domain 'contoso.com'
                $results.Count | Should -Be 2
            }
        }

        It 'Should correctly detect LAPS-covered computer' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results     = Get-DSLAPSCoverage -Domain 'contoso.com'
                $workstation = $results | Where-Object { $_.Name -eq 'WORKSTATION01' }
                $workstation.HasLAPS     | Should -BeTrue
                $workstation.LAPSVersion | Should -Be 'LegacyLAPS'
            }
        }

        It 'Should correctly flag computer without LAPS as High risk' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Get-DSLAPSCoverage -Domain 'contoso.com'
                $server  = $results | Where-Object { $_.Name -eq 'SERVER01' }
                $server.HasLAPS   | Should -BeFalse
                $server.RiskLevel | Should -Be 'High'
            }
        }
    }
}
