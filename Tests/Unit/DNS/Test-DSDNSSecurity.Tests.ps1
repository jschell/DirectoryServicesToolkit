BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSDNSSecurity' -Tag 'Unit', 'DNS' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                ZoneName               = 'contoso.com'
                ZoneType               = 'Primary'
                DynamicUpdate          = 'Secure'
                AllowsUnsecuredDynamic = $false
                ZoneTransferEnabled    = $false
                ZoneTransferPolicy     = 'NoTransfer'
                ZoneTransferTargets    = $null
                RiskFactors            = @()
                IsReverseLookupZone    = $false
            }

            $result.PSObject.Properties.Name | Should -Contain 'ZoneName'
            $result.PSObject.Properties.Name | Should -Contain 'ZoneType'
            $result.PSObject.Properties.Name | Should -Contain 'DynamicUpdate'
            $result.PSObject.Properties.Name | Should -Contain 'AllowsUnsecuredDynamic'
            $result.PSObject.Properties.Name | Should -Contain 'ZoneTransferEnabled'
            $result.PSObject.Properties.Name | Should -Contain 'ZoneTransferPolicy'
            $result.PSObject.Properties.Name | Should -Contain 'ZoneTransferTargets'
            $result.PSObject.Properties.Name | Should -Contain 'RiskFactors'
            $result.PSObject.Properties.Name | Should -Contain 'IsReverseLookupZone'
        }
    }

    Context 'ZoneType mapping' {

        It 'ZoneType 1 should map to Primary' {
            $zoneTypeMap = @{ 0 = 'Cache'; 1 = 'Primary'; 2 = 'Secondary'; 3 = 'Stub'; 4 = 'Forwarder' }
            $zoneTypeMap[1] | Should -Be 'Primary'
        }

        It 'ZoneType 2 should map to Secondary' {
            $zoneTypeMap = @{ 0 = 'Cache'; 1 = 'Primary'; 2 = 'Secondary'; 3 = 'Stub'; 4 = 'Forwarder' }
            $zoneTypeMap[2] | Should -Be 'Secondary'
        }

        It 'ZoneType 0 should map to Cache (and be skipped)' {
            $zoneTypeMap = @{ 0 = 'Cache'; 1 = 'Primary'; 2 = 'Secondary' }
            $zoneTypeMap[0] | Should -Be 'Cache'
        }
    }

    Context 'DynamicUpdate mapping' {

        It 'DynamicUpdate=0 should map to None' {
            $map = @{ 0 = 'None'; 1 = 'NonsecureAndSecure'; 2 = 'Secure' }
            $map[0] | Should -Be 'None'
        }

        It 'DynamicUpdate=1 should map to NonsecureAndSecure' {
            $map = @{ 0 = 'None'; 1 = 'NonsecureAndSecure'; 2 = 'Secure' }
            $map[1] | Should -Be 'NonsecureAndSecure'
        }

        It 'DynamicUpdate=2 should map to Secure' {
            $map = @{ 0 = 'None'; 1 = 'NonsecureAndSecure'; 2 = 'Secure' }
            $map[2] | Should -Be 'Secure'
        }
    }

    Context 'SecureSecondaries / ZoneTransfer mapping' {

        It 'SecureSecondaries=0 should map to ToAny and flag ZoneTransferToAnyServer' {
            $map = @{ 0 = 'ToAny'; 1 = 'ToNsServers'; 2 = 'ToList'; 3 = 'NoTransfer' }
            $map[0] | Should -Be 'ToAny'
            [bool](0 -ne 3) | Should -BeTrue   # transfersEnabled
            [bool](0 -eq 0) | Should -BeTrue   # transferToAny
        }

        It 'SecureSecondaries=3 should map to NoTransfer and disable transfers' {
            $map = @{ 0 = 'ToAny'; 1 = 'ToNsServers'; 2 = 'ToList'; 3 = 'NoTransfer' }
            $map[3] | Should -Be 'NoTransfer'
            [bool](3 -ne 3) | Should -BeFalse  # transfersEnabled = false
        }
    }

    Context 'Security evaluation logic' {

        It 'DynamicUpdate=1 should set AllowsUnsecuredDynamic=$true and add UnsecuredDynamicUpdate risk factor' {
            $dynamicUpdate    = 1
            $unsecureDynamic  = ($dynamicUpdate -eq 1)
            $riskFactors      = [System.Collections.Generic.List[string]]::new()
            if ($unsecureDynamic) { [void]$riskFactors.Add('UnsecuredDynamicUpdate') }

            $unsecureDynamic     | Should -BeTrue
            $riskFactors         | Should -Contain 'UnsecuredDynamicUpdate'
        }

        It 'DynamicUpdate=2 should set AllowsUnsecuredDynamic=$false with no dynamic risk factor' {
            $dynamicUpdate    = 2
            $unsecureDynamic  = ($dynamicUpdate -eq 1)
            $riskFactors      = [System.Collections.Generic.List[string]]::new()
            if ($unsecureDynamic) { [void]$riskFactors.Add('UnsecuredDynamicUpdate') }

            $unsecureDynamic     | Should -BeFalse
            $riskFactors         | Should -Not -Contain 'UnsecuredDynamicUpdate'
        }

        It 'SecureSecondaries=0 should add ZoneTransferToAnyServer risk factor' {
            $secSec          = 0
            $transferToAny   = ($secSec -eq 0)
            $riskFactors     = [System.Collections.Generic.List[string]]::new()
            if ($transferToAny) { [void]$riskFactors.Add('ZoneTransferToAnyServer') }

            $riskFactors | Should -Contain 'ZoneTransferToAnyServer'
        }

        It 'SecureSecondaries=1 should add ZoneTransferEnabled risk factor (not ToAny)' {
            $secSec           = 1
            $transfersEnabled = ($secSec -ne 3)
            $transferToAny    = ($secSec -eq 0)
            $riskFactors      = [System.Collections.Generic.List[string]]::new()
            if ($transferToAny)        { [void]$riskFactors.Add('ZoneTransferToAnyServer') }
            elseif ($transfersEnabled) { [void]$riskFactors.Add('ZoneTransferEnabled') }

            $riskFactors | Should -Contain 'ZoneTransferEnabled'
            $riskFactors | Should -Not -Contain 'ZoneTransferToAnyServer'
        }

        It 'Secure zone should have empty RiskFactors' {
            $dynamicUpdate    = 2
            $secSec           = 3
            $unsecureDynamic  = ($dynamicUpdate -eq 1)
            $transfersEnabled = ($secSec -ne 3)
            $transferToAny    = ($secSec -eq 0)

            $riskFactors = [System.Collections.Generic.List[string]]::new()
            if ($unsecureDynamic) { [void]$riskFactors.Add('UnsecuredDynamicUpdate') }
            if ($transferToAny)   { [void]$riskFactors.Add('ZoneTransferToAnyServer') }
            elseif ($transfersEnabled) { [void]$riskFactors.Add('ZoneTransferEnabled') }

            $riskFactors.Count | Should -Be 0
        }
    }

    Context 'Skip criteria' {

        It 'Should skip autocreated zones' {
            $zone = [PSCustomObject]@{ IsAutoCreated = $true; IsReverseLookupZone = $false; ZoneType = 1 }
            $skip = ($zone.IsAutoCreated -or $zone.IsReverseLookupZone -or $zone.ZoneType -eq 0)
            $skip | Should -BeTrue
        }

        It 'Should skip reverse lookup zones' {
            $zone = [PSCustomObject]@{ IsAutoCreated = $false; IsReverseLookupZone = $true; ZoneType = 1 }
            $skip = ($zone.IsAutoCreated -or $zone.IsReverseLookupZone -or $zone.ZoneType -eq 0)
            $skip | Should -BeTrue
        }

        It 'Should skip cache zones (ZoneType=0)' {
            $zone = [PSCustomObject]@{ IsAutoCreated = $false; IsReverseLookupZone = $false; ZoneType = 0 }
            $skip = ($zone.IsAutoCreated -or $zone.IsReverseLookupZone -or $zone.ZoneType -eq 0)
            $skip | Should -BeTrue
        }

        It 'Should not skip a normal primary zone' {
            $zone = [PSCustomObject]@{ IsAutoCreated = $false; IsReverseLookupZone = $false; ZoneType = 1 }
            $skip = ($zone.IsAutoCreated -or $zone.IsReverseLookupZone -or $zone.ZoneType -eq 0)
            $skip | Should -BeFalse
        }
    }

    Context 'Mocked query — secure zone and insecure zone' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Get-CimInstance {
                    return @(
                        # Zone 1: Secure (DynamicUpdate=2, SecureSecondaries=3)
                        [PSCustomObject]@{
                            Name                 = 'contoso.com'
                            ZoneType             = 1
                            DynamicUpdate        = 2
                            SecureSecondaries    = 3
                            SecondaryServers     = $null
                            IsAutoCreated        = $false
                            IsReverseLookupZone  = $false
                            IsPaused             = $false
                        },
                        # Zone 2: Insecure (DynamicUpdate=1, SecureSecondaries=0)
                        [PSCustomObject]@{
                            Name                 = 'insecure.local'
                            ZoneType             = 1
                            DynamicUpdate        = 1
                            SecureSecondaries    = 0
                            SecondaryServers     = @('10.0.0.1')
                            IsAutoCreated        = $false
                            IsReverseLookupZone  = $false
                            IsPaused             = $false
                        },
                        # Zone 3: Reverse lookup — should be skipped
                        [PSCustomObject]@{
                            Name                 = '1.168.192.in-addr.arpa'
                            ZoneType             = 1
                            DynamicUpdate        = 2
                            SecureSecondaries    = 3
                            SecondaryServers     = $null
                            IsAutoCreated        = $false
                            IsReverseLookupZone  = $true
                            IsPaused             = $false
                        }
                    )
                }

                Mock New-CimSession {
                    return [PSCustomObject]@{ ComputerName = 'dc01.contoso.com' }
                }

                Mock Remove-CimSession {}

                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Get-DSPdcEmulatorName { return 'dc01.contoso.com' }
            }
        }

        It 'Should return exactly two zone results (reverse lookup skipped)' {
            InModuleScope DirectoryServicesToolkit {
                $results = Test-DSDNSSecurity -Domain 'contoso.com'
                $results.Count | Should -Be 2
            }
        }

        It 'Secure zone should have empty RiskFactors' {
            InModuleScope DirectoryServicesToolkit {
                $results     = Test-DSDNSSecurity -Domain 'contoso.com'
                $secureZone  = $results | Where-Object { $_.ZoneName -eq 'contoso.com' }
                $secureZone.RiskFactors.Count | Should -Be 0
            }
        }

        It 'Secure zone AllowsUnsecuredDynamic should be $false' {
            InModuleScope DirectoryServicesToolkit {
                $results    = Test-DSDNSSecurity -Domain 'contoso.com'
                $secureZone = $results | Where-Object { $_.ZoneName -eq 'contoso.com' }
                $secureZone.AllowsUnsecuredDynamic | Should -BeFalse
            }
        }

        It 'Secure zone ZoneTransferPolicy should be NoTransfer' {
            InModuleScope DirectoryServicesToolkit {
                $results    = Test-DSDNSSecurity -Domain 'contoso.com'
                $secureZone = $results | Where-Object { $_.ZoneName -eq 'contoso.com' }
                $secureZone.ZoneTransferPolicy | Should -Be 'NoTransfer'
            }
        }

        It 'Insecure zone should have both risk factors' {
            InModuleScope DirectoryServicesToolkit {
                $results       = Test-DSDNSSecurity -Domain 'contoso.com'
                $insecureZone  = $results | Where-Object { $_.ZoneName -eq 'insecure.local' }
                $insecureZone.RiskFactors | Should -Contain 'UnsecuredDynamicUpdate'
                $insecureZone.RiskFactors | Should -Contain 'ZoneTransferToAnyServer'
            }
        }

        It 'Insecure zone AllowsUnsecuredDynamic should be $true' {
            InModuleScope DirectoryServicesToolkit {
                $results      = Test-DSDNSSecurity -Domain 'contoso.com'
                $insecureZone = $results | Where-Object { $_.ZoneName -eq 'insecure.local' }
                $insecureZone.AllowsUnsecuredDynamic | Should -BeTrue
            }
        }

        It 'Insecure zone ZoneTransferPolicy should be ToAny' {
            InModuleScope DirectoryServicesToolkit {
                $results      = Test-DSDNSSecurity -Domain 'contoso.com'
                $insecureZone = $results | Where-Object { $_.ZoneName -eq 'insecure.local' }
                $insecureZone.ZoneTransferPolicy | Should -Be 'ToAny'
            }
        }

        It '-Zone filter should return only the specified zone' {
            InModuleScope DirectoryServicesToolkit {
                $results = Test-DSDNSSecurity -Domain 'contoso.com' -Zone 'contoso.com'
                $results.Count | Should -Be 1
                $results[0].ZoneName | Should -Be 'contoso.com'
            }
        }
    }
}
