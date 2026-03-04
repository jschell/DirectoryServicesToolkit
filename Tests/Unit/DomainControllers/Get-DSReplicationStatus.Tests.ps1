BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSReplicationStatus' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DCName                = 'dc01.contoso.com'
                Partner               = 'dc02.contoso.com'
                NamingContext         = 'DC=contoso,DC=com'
                LastAttempted         = (Get-Date)
                LastSuccessful        = (Get-Date)
                ConsecutiveFailures   = 0
                LastSyncResult        = 0
                LastSyncResultMessage = 'Success'
                IsFailing             = $false
            }

            $result.PSObject.Properties.Name | Should -Contain 'DCName'
            $result.PSObject.Properties.Name | Should -Contain 'Partner'
            $result.PSObject.Properties.Name | Should -Contain 'NamingContext'
            $result.PSObject.Properties.Name | Should -Contain 'LastAttempted'
            $result.PSObject.Properties.Name | Should -Contain 'LastSuccessful'
            $result.PSObject.Properties.Name | Should -Contain 'ConsecutiveFailures'
            $result.PSObject.Properties.Name | Should -Contain 'LastSyncResult'
            $result.PSObject.Properties.Name | Should -Contain 'LastSyncResultMessage'
            $result.PSObject.Properties.Name | Should -Contain 'IsFailing'
        }
    }

    Context 'IsFailing logic' {

        It 'IsFailing should be $true when ConsecutiveFailures > 0' {
            $consFailures = 3
            $lastResult   = 0
            $isFailing    = ($consFailures -gt 0 -or $lastResult -ne 0)
            $isFailing    | Should -BeTrue
        }

        It 'IsFailing should be $true when LastSyncResult != 0' {
            $consFailures = 0
            $lastResult   = 8453
            $isFailing    = ($consFailures -gt 0 -or $lastResult -ne 0)
            $isFailing    | Should -BeTrue
        }

        It 'IsFailing should be $false when ConsecutiveFailures=0 and LastSyncResult=0' {
            $consFailures = 0
            $lastResult   = 0
            $isFailing    = ($consFailures -gt 0 -or $lastResult -ne 0)
            $isFailing    | Should -BeFalse
        }
    }

    Context 'LastSyncResultMessage' {

        It 'LastSyncResult=0 should produce Success message' {
            $lastResult = 0
            $msg        = if ($lastResult -eq 0) { 'Success' } else { "Win32 error $lastResult" }
            $msg        | Should -Be 'Success'
        }

        It 'Non-zero LastSyncResult should produce a non-Success message' {
            $lastResult = 8453
            $msg        = if ($lastResult -eq 0) { 'Success' } else { "Win32 error $lastResult" }
            $msg        | Should -Not -Be 'Success'
        }
    }

    Context 'ShowFailuresOnly filter logic' {

        It 'Should skip healthy entries when ShowFailuresOnly is $true' {
            $showFailuresOnly = $true
            $isFailing        = $false
            $skip             = ($showFailuresOnly -and -not $isFailing)
            $skip             | Should -BeTrue
        }

        It 'Should include failing entries when ShowFailuresOnly is $true' {
            $showFailuresOnly = $true
            $isFailing        = $true
            $skip             = ($showFailuresOnly -and -not $isFailing)
            $skip             | Should -BeFalse
        }

        It 'Should include healthy entries when ShowFailuresOnly is $false' {
            $showFailuresOnly = $false
            $isFailing        = $false
            $skip             = ($showFailuresOnly -and -not $isFailing)
            $skip             | Should -BeFalse
        }
    }

    Context 'Mocked query — one DC with two replication neighbors' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {

                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Get-DSDomainControllerNames { return @('dc01.contoso.com') }
                Mock Get-DSReplicationNeighborData {
                    return @(
                        [PSCustomObject]@{
                            SourceServer            = 'dc02.contoso.com'
                            PartitionName           = 'DC=contoso,DC=com'
                            LastAttemptedSync       = [datetime]'2026-03-03T10:00:00'
                            LastSuccessfulSync      = [datetime]'2026-03-03T10:00:00'
                            ConsecutiveFailureCount = 0
                            LastSyncResult          = 0
                        },
                        [PSCustomObject]@{
                            SourceServer            = 'dc02.contoso.com'
                            PartitionName           = 'CN=Configuration,DC=contoso,DC=com'
                            LastAttemptedSync       = [datetime]'2026-03-03T09:00:00'
                            LastSuccessfulSync      = [datetime]'2026-03-02T10:00:00'
                            ConsecutiveFailureCount = 3
                            LastSyncResult          = 8453
                        }
                    )
                }
            }
        }

        It 'Should return two results (one per neighbor)' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSReplicationStatus -Domain 'contoso.com'
                $results.Count | Should -Be 2
            }
        }

        It 'Healthy neighbor should have IsFailing=$false and LastSyncResultMessage=Success' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSReplicationStatus -Domain 'contoso.com'
                $good    = $results | Where-Object { $_.ConsecutiveFailures -eq 0 }
                $good.IsFailing             | Should -BeFalse
                $good.LastSyncResultMessage | Should -Be 'Success'
            }
        }

        It 'Failing neighbor should have IsFailing=$true' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSReplicationStatus -Domain 'contoso.com'
                $bad     = $results | Where-Object { $_.ConsecutiveFailures -gt 0 }
                $bad.IsFailing           | Should -BeTrue
                $bad.ConsecutiveFailures | Should -Be 3
                $bad.LastSyncResult      | Should -Be 8453
            }
        }

        It '-ShowFailuresOnly should return only the failing neighbor' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSReplicationStatus -Domain 'contoso.com' -ShowFailuresOnly
                $results.Count          | Should -Be 1
                $results[0].IsFailing   | Should -BeTrue
            }
        }

        It 'DCName should be the queried DC name' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSReplicationStatus -Domain 'contoso.com'
                $results | ForEach-Object { $_.DCName | Should -Be 'dc01.contoso.com' }
            }
        }

        It 'Partner should be dc02.contoso.com for both entries' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSReplicationStatus -Domain 'contoso.com'
                $results | ForEach-Object { $_.Partner | Should -Be 'dc02.contoso.com' }
            }
        }
    }
}
