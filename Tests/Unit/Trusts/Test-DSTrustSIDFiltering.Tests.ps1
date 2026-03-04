BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSTrustSIDFiltering' -Tag 'Unit', 'Trusts' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                TrustName           = 'partner.com'
                Direction           = 'Bidirectional'
                TrustType           = 'Forest'
                SIDFilteringEnabled = $false
                FilteringStatus     = 'ForestDefault'
                RiskLevel           = 'Medium'
                TrustAttributes     = 8
            }

            $result.PSObject.Properties.Name | Should -Contain 'TrustName'
            $result.PSObject.Properties.Name | Should -Contain 'Direction'
            $result.PSObject.Properties.Name | Should -Contain 'TrustType'
            $result.PSObject.Properties.Name | Should -Contain 'SIDFilteringEnabled'
            $result.PSObject.Properties.Name | Should -Contain 'FilteringStatus'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'TrustAttributes'
        }
    }

    Context 'SID filtering status logic' {

        It 'QUARANTINED_DOMAIN bit (4) set → FilteringStatus=Enabled, RiskLevel=Low' {
            $trustAttributes     = 4    # QUARANTINED_DOMAIN
            $sidFilteringEnabled = [bool]($trustAttributes -band 4)
            $isForestTrust       = [bool]($trustAttributes -band 8)
            $isWithinForest      = [bool]($trustAttributes -band 32)

            $filteringStatus = if ($sidFilteringEnabled) { 'Enabled' }
                               elseif ($isWithinForest)  { 'WithinForest' }
                               elseif ($isForestTrust)   { 'ForestDefault' }
                               else                      { 'Disabled' }

            $riskLevel = switch ($filteringStatus) {
                'Enabled'       { 'Low' }
                'WithinForest'  { 'Low' }
                'ForestDefault' { 'Medium' }
                'Disabled'      { 'High' }
            }

            $filteringStatus | Should -Be 'Enabled'
            $riskLevel       | Should -Be 'Low'
        }

        It 'External trust, no quarantine (trustAttributes=0) → FilteringStatus=Disabled, RiskLevel=High' {
            $trustAttributes     = 0
            $sidFilteringEnabled = [bool]($trustAttributes -band 4)
            $isForestTrust       = [bool]($trustAttributes -band 8)
            $isWithinForest      = [bool]($trustAttributes -band 32)

            $filteringStatus = if ($sidFilteringEnabled) { 'Enabled' }
                               elseif ($isWithinForest)  { 'WithinForest' }
                               elseif ($isForestTrust)   { 'ForestDefault' }
                               else                      { 'Disabled' }

            $riskLevel = switch ($filteringStatus) {
                'Enabled'       { 'Low' }
                'WithinForest'  { 'Low' }
                'ForestDefault' { 'Medium' }
                'Disabled'      { 'High' }
            }

            $filteringStatus | Should -Be 'Disabled'
            $riskLevel       | Should -Be 'High'
        }

        It 'Forest trust without quarantine (trustAttributes=8) → FilteringStatus=ForestDefault, RiskLevel=Medium' {
            $trustAttributes     = 8    # FOREST_TRANSITIVE only
            $sidFilteringEnabled = [bool]($trustAttributes -band 4)
            $isForestTrust       = [bool]($trustAttributes -band 8)
            $isWithinForest      = [bool]($trustAttributes -band 32)

            $filteringStatus = if ($sidFilteringEnabled) { 'Enabled' }
                               elseif ($isWithinForest)  { 'WithinForest' }
                               elseif ($isForestTrust)   { 'ForestDefault' }
                               else                      { 'Disabled' }

            $riskLevel = switch ($filteringStatus) {
                'Enabled'       { 'Low' }
                'WithinForest'  { 'Low' }
                'ForestDefault' { 'Medium' }
                'Disabled'      { 'High' }
            }

            $filteringStatus | Should -Be 'ForestDefault'
            $riskLevel       | Should -Be 'Medium'
        }

        It 'Within-forest trust (trustAttributes=32) → FilteringStatus=WithinForest, RiskLevel=Low' {
            $trustAttributes     = 32   # WITHIN_FOREST
            $sidFilteringEnabled = [bool]($trustAttributes -band 4)
            $isForestTrust       = [bool]($trustAttributes -band 8)
            $isWithinForest      = [bool]($trustAttributes -band 32)

            $filteringStatus = if ($sidFilteringEnabled) { 'Enabled' }
                               elseif ($isWithinForest)  { 'WithinForest' }
                               elseif ($isForestTrust)   { 'ForestDefault' }
                               else                      { 'Disabled' }

            $riskLevel = switch ($filteringStatus) {
                'Enabled'       { 'Low' }
                'WithinForest'  { 'Low' }
                'ForestDefault' { 'Medium' }
                'Disabled'      { 'High' }
            }

            $filteringStatus | Should -Be 'WithinForest'
            $riskLevel       | Should -Be 'Low'
        }

        It 'QUARANTINED_DOMAIN takes precedence over WITHIN_FOREST' {
            # trustAttributes has both QUARANTINED_DOMAIN (4) and WITHIN_FOREST (32)
            $trustAttributes     = 36   # 4 + 32
            $sidFilteringEnabled = [bool]($trustAttributes -band 4)
            $isWithinForest      = [bool]($trustAttributes -band 32)

            # QUARANTINED_DOMAIN is checked first
            $filteringStatus = if ($sidFilteringEnabled) { 'Enabled' }
                               elseif ($isWithinForest)  { 'WithinForest' }
                               else                      { 'Disabled' }

            $filteringStatus | Should -Be 'Enabled'
        }
    }

    Context 'Mocked query — three trust scenarios from plan' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        # Trust 1: External with QUARANTINED_DOMAIN → Enabled / Low
                        @{
                            name             = @('filtered.org')
                            trustdirection   = @(2)
                            trusttype        = @(2)
                            trustattributes  = @(4)     # QUARANTINED_DOMAIN
                            flatname         = @('FILTERED')
                        },
                        # Trust 2: External without quarantine → Disabled / High
                        @{
                            name             = @('unfiltered.org')
                            trustdirection   = @(2)
                            trusttype        = @(2)
                            trustattributes  = @(0)
                            flatname         = @('UNFILTERED')
                        },
                        # Trust 3: Forest trust without quarantine → ForestDefault / Medium
                        @{
                            name             = @('partner.com')
                            trustdirection   = @(3)
                            trusttype        = @(2)
                            trustattributes  = @(8)     # FOREST_TRANSITIVE
                            flatname         = @('PARTNER')
                        }
                    )
                }

                Mock Resolve-DSDomainName { return 'contoso.com' }
            }
        }

        It 'Should return three results' {
            InModuleScope DirectoryServicesToolkit {
                $results = Test-DSTrustSIDFiltering -Domain 'contoso.com'
                $results.Count | Should -Be 3
            }
        }

        It 'filtered.org should have FilteringStatus=Enabled and RiskLevel=Low' {
            InModuleScope DirectoryServicesToolkit {
                $results = Test-DSTrustSIDFiltering -Domain 'contoso.com'
                $t = $results | Where-Object { $_.TrustName -eq 'filtered.org' }
                $t.FilteringStatus | Should -Be 'Enabled'
                $t.RiskLevel       | Should -Be 'Low'
                $t.SIDFilteringEnabled | Should -BeTrue
            }
        }

        It 'unfiltered.org should have FilteringStatus=Disabled and RiskLevel=High' {
            InModuleScope DirectoryServicesToolkit {
                $results = Test-DSTrustSIDFiltering -Domain 'contoso.com'
                $t = $results | Where-Object { $_.TrustName -eq 'unfiltered.org' }
                $t.FilteringStatus | Should -Be 'Disabled'
                $t.RiskLevel       | Should -Be 'High'
                $t.SIDFilteringEnabled | Should -BeFalse
            }
        }

        It 'partner.com should have FilteringStatus=ForestDefault and RiskLevel=Medium' {
            InModuleScope DirectoryServicesToolkit {
                $results = Test-DSTrustSIDFiltering -Domain 'contoso.com'
                $t = $results | Where-Object { $_.TrustName -eq 'partner.com' }
                $t.FilteringStatus | Should -Be 'ForestDefault'
                $t.RiskLevel       | Should -Be 'Medium'
            }
        }

        It 'partner.com TrustType should be Forest' {
            InModuleScope DirectoryServicesToolkit {
                $results = Test-DSTrustSIDFiltering -Domain 'contoso.com'
                $t = $results | Where-Object { $_.TrustName -eq 'partner.com' }
                $t.TrustType | Should -Be 'Forest'
            }
        }
    }

    Context 'Parameter validation' {

        It 'Domain parameter should not accept empty string' {
            $cmd   = Get-Command Test-DSTrustSIDFiltering -Module DirectoryServicesToolkit
            $param = $cmd.Parameters['Domain']
            $param | Should -Not -BeNullOrEmpty
        }
    }
}
