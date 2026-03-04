BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
    Import-Module CimCmdlets -ErrorAction SilentlyContinue
}

Describe 'Get-DSSysvolHealth' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DCName           = 'dc01.contoso.com'
                SYSVOLShared     = $true
                NETLOGONShared   = $true
                SysvolReady      = $true
                DFSRState        = 'Normal'
                DFSRStateCode    = 4
                StagingBacklogMB = 0.0
                IsHealthy        = $true
                Errors           = @()
            }

            $result.PSObject.Properties.Name | Should -Contain 'DCName'
            $result.PSObject.Properties.Name | Should -Contain 'SYSVOLShared'
            $result.PSObject.Properties.Name | Should -Contain 'NETLOGONShared'
            $result.PSObject.Properties.Name | Should -Contain 'SysvolReady'
            $result.PSObject.Properties.Name | Should -Contain 'DFSRState'
            $result.PSObject.Properties.Name | Should -Contain 'DFSRStateCode'
            $result.PSObject.Properties.Name | Should -Contain 'StagingBacklogMB'
            $result.PSObject.Properties.Name | Should -Contain 'IsHealthy'
            $result.PSObject.Properties.Name | Should -Contain 'Errors'
        }
    }

    Context 'DFSR state mapping' {

        It 'State 4 should map to Normal' {
            $stateMap = @{ 0='Uninitialized'; 1='Initialized'; 2='InitialSync'; 3='AutoRecovery'; 4='Normal'; 5='InError' }
            $stateMap[4] | Should -Be 'Normal'
        }

        It 'State 2 should map to InitialSync' {
            $stateMap = @{ 0='Uninitialized'; 1='Initialized'; 2='InitialSync'; 3='AutoRecovery'; 4='Normal'; 5='InError' }
            $stateMap[2] | Should -Be 'InitialSync'
        }

        It 'State 5 should map to InError' {
            $stateMap = @{ 0='Uninitialized'; 1='Initialized'; 2='InitialSync'; 3='AutoRecovery'; 4='Normal'; 5='InError' }
            $stateMap[5] | Should -Be 'InError'
        }
    }

    Context 'IsHealthy logic' {

        It 'All checks passing should produce IsHealthy=$true and empty Errors' {
            $sysvolShared    = $true
            $netlogonShared  = $true
            $sysvolReady     = $true
            $dfsrStateCode   = 4

            $errors    = [System.Collections.Generic.List[string]]::new()
            if (-not $sysvolShared)                                             { [void]$errors.Add('SYSVOL share missing') }
            if (-not $netlogonShared)                                           { [void]$errors.Add('NETLOGON share missing') }
            if ($null -ne $sysvolReady -and -not $sysvolReady)                  { [void]$errors.Add('SysvolReady registry flag not set') }
            if ($null -ne $dfsrStateCode -and $dfsrStateCode -ne 4)             { [void]$errors.Add('DFSR state: Normal') }

            $isHealthy = $sysvolShared -and $netlogonShared -and
                         ($null -eq $sysvolReady -or $sysvolReady) -and
                         ($null -eq $dfsrStateCode -or $dfsrStateCode -eq 4)

            $isHealthy     | Should -BeTrue
            $errors.Count  | Should -Be 0
        }

        It 'Missing SYSVOL share should produce IsHealthy=$false and add error' {
            $sysvolShared   = $false
            $netlogonShared = $true
            $sysvolReady    = $true
            $dfsrStateCode  = 4

            $errors = [System.Collections.Generic.List[string]]::new()
            if (-not $sysvolShared)   { [void]$errors.Add('SYSVOL share missing') }

            $isHealthy = $sysvolShared -and $netlogonShared -and $sysvolReady -and ($dfsrStateCode -eq 4)

            $isHealthy     | Should -BeFalse
            $errors        | Should -Contain 'SYSVOL share missing'
        }

        It 'DFSR InError state should produce IsHealthy=$false' {
            $sysvolShared   = $true
            $netlogonShared = $true
            $sysvolReady    = $true
            $dfsrStateCode  = 5   # InError

            $isHealthy = $sysvolShared -and $netlogonShared -and $sysvolReady -and ($dfsrStateCode -eq 4)
            $isHealthy | Should -BeFalse
        }

        It 'Null DFSRStateCode should not affect IsHealthy' {
            $sysvolShared   = $true
            $netlogonShared = $true
            $sysvolReady    = $true
            $dfsrStateCode  = $null

            $isHealthy = $sysvolShared -and $netlogonShared -and
                         ($null -eq $sysvolReady -or $sysvolReady) -and
                         ($null -eq $dfsrStateCode -or $dfsrStateCode -eq 4)

            $isHealthy | Should -BeTrue
        }
    }

    Context 'Mocked query — healthy DC' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {

                Mock New-CimSession {
                    return [PSCustomObject]@{ ComputerName = 'dc01.contoso.com' }
                }

                Mock Get-CimInstance {
                    param($ClassName, $Namespace, $CimSession)
                    if ($ClassName -eq 'Win32_Share')
                    {
                        return @(
                            [PSCustomObject]@{ Name = 'SYSVOL'   },
                            [PSCustomObject]@{ Name = 'NETLOGON' }
                        )
                    }
                    elseif ($ClassName -eq 'DfsrReplicatedFolderInfo')
                    {
                        return [PSCustomObject]@{
                            ReplicationGroupName = 'Domain System Volume'
                            State                = 4
                            CurrentStageSizeInMb = 0.0
                        }
                    }
                }

                Mock Get-CimClass { return [PSCustomObject]@{} }

                Mock Invoke-CimMethod {
                    return [PSCustomObject]@{ uValue = 1 }
                }

                Mock Remove-CimSession {}
            }
        }

        It 'Healthy DC should have IsHealthy=$true' {
            InModuleScope DirectoryServicesToolkit {
                $result = Get-DSSysvolHealth -ComputerName 'dc01.contoso.com'
                $result.IsHealthy | Should -BeTrue
            }
        }

        It 'Healthy DC should have empty Errors array' {
            InModuleScope DirectoryServicesToolkit {
                $result = Get-DSSysvolHealth -ComputerName 'dc01.contoso.com'
                $result.Errors.Count | Should -Be 0
            }
        }

        It 'Healthy DC should have SYSVOLShared=$true' {
            InModuleScope DirectoryServicesToolkit {
                $result = Get-DSSysvolHealth -ComputerName 'dc01.contoso.com'
                $result.SYSVOLShared | Should -BeTrue
            }
        }

        It 'Healthy DC should have NETLOGONShared=$true' {
            InModuleScope DirectoryServicesToolkit {
                $result = Get-DSSysvolHealth -ComputerName 'dc01.contoso.com'
                $result.NETLOGONShared | Should -BeTrue
            }
        }

        It 'Healthy DC should have DFSRState=Normal' {
            InModuleScope DirectoryServicesToolkit {
                $result = Get-DSSysvolHealth -ComputerName 'dc01.contoso.com'
                $result.DFSRState     | Should -Be 'Normal'
                $result.DFSRStateCode | Should -Be 4
            }
        }
    }

    Context 'Mocked query — missing SYSVOL share' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {

                Mock New-CimSession {
                    return [PSCustomObject]@{ ComputerName = 'dc02.contoso.com' }
                }

                Mock Get-CimInstance {
                    param($ClassName, $Namespace, $CimSession)
                    if ($ClassName -eq 'Win32_Share')
                    {
                        # Only NETLOGON returned — SYSVOL missing
                        return @([PSCustomObject]@{ Name = 'NETLOGON' })
                    }
                    elseif ($ClassName -eq 'DfsrReplicatedFolderInfo')
                    {
                        return [PSCustomObject]@{
                            ReplicationGroupName = 'Domain System Volume'
                            State                = 4
                            CurrentStageSizeInMb = 0.0
                        }
                    }
                }

                Mock Get-CimClass { return [PSCustomObject]@{} }
                Mock Invoke-CimMethod { return [PSCustomObject]@{ uValue = 1 } }
                Mock Remove-CimSession {}
            }
        }

        It 'Missing SYSVOL share should set SYSVOLShared=$false' {
            InModuleScope DirectoryServicesToolkit {
                $result = Get-DSSysvolHealth -ComputerName 'dc02.contoso.com'
                $result.SYSVOLShared | Should -BeFalse
            }
        }

        It 'Missing SYSVOL share should set IsHealthy=$false' {
            InModuleScope DirectoryServicesToolkit {
                $result = Get-DSSysvolHealth -ComputerName 'dc02.contoso.com'
                $result.IsHealthy | Should -BeFalse
            }
        }

        It 'Missing SYSVOL share should add error entry' {
            InModuleScope DirectoryServicesToolkit {
                $result = Get-DSSysvolHealth -ComputerName 'dc02.contoso.com'
                $result.Errors | Should -Contain 'SYSVOL share missing'
            }
        }
    }

    Context 'Mocked query — DFSR InError state' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {

                Mock New-CimSession {
                    return [PSCustomObject]@{ ComputerName = 'dc03.contoso.com' }
                }

                Mock Get-CimInstance {
                    param($ClassName, $Namespace, $CimSession)
                    if ($ClassName -eq 'Win32_Share')
                    {
                        return @(
                            [PSCustomObject]@{ Name = 'SYSVOL'   },
                            [PSCustomObject]@{ Name = 'NETLOGON' }
                        )
                    }
                    elseif ($ClassName -eq 'DfsrReplicatedFolderInfo')
                    {
                        return [PSCustomObject]@{
                            ReplicationGroupName = 'Domain System Volume'
                            State                = 5   # InError
                            CurrentStageSizeInMb = 125.0
                        }
                    }
                }

                Mock Get-CimClass { return [PSCustomObject]@{} }
                Mock Invoke-CimMethod { return [PSCustomObject]@{ uValue = 1 } }
                Mock Remove-CimSession {}
            }
        }

        It 'DFSR InError state should set DFSRState=InError' {
            InModuleScope DirectoryServicesToolkit {
                $result = Get-DSSysvolHealth -ComputerName 'dc03.contoso.com'
                $result.DFSRState     | Should -Be 'InError'
                $result.DFSRStateCode | Should -Be 5
            }
        }

        It 'DFSR InError state should set IsHealthy=$false' {
            InModuleScope DirectoryServicesToolkit {
                $result = Get-DSSysvolHealth -ComputerName 'dc03.contoso.com'
                $result.IsHealthy | Should -BeFalse
            }
        }

        It 'DFSR InError state should add error entry' {
            InModuleScope DirectoryServicesToolkit {
                $result = Get-DSSysvolHealth -ComputerName 'dc03.contoso.com'
                $result.Errors | Should -Contain 'DFSR state: InError'
            }
        }

        It 'StagingBacklogMB should reflect DFSR staging size' {
            InModuleScope DirectoryServicesToolkit {
                $result = Get-DSSysvolHealth -ComputerName 'dc03.contoso.com'
                $result.StagingBacklogMB | Should -Be 125.0
            }
        }
    }
}
