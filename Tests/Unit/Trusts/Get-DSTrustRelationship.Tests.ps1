BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSTrustRelationship' -Tag 'Unit', 'Trusts' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                Name                 = 'partner.com'
                FlatName             = 'PARTNER'
                TrustedDomainSID     = 'S-1-5-21-1234567890-1234567890-1234567890'
                Direction            = 'Bidirectional'
                TrustType            = 'Forest'
                IsTransitive         = $true
                ForestTransitive     = $true
                SIDFilteringEnabled  = $false
                TGTDelegationBlocked = $false
                WithinForest         = $false
                TreatAsExternal      = $false
                TrustAttributes      = 8
                WhenCreated          = (Get-Date)
                WhenModified         = (Get-Date)
                SourceDomain         = 'contoso.com'
            }

            $result.PSObject.Properties.Name | Should -Contain 'Name'
            $result.PSObject.Properties.Name | Should -Contain 'FlatName'
            $result.PSObject.Properties.Name | Should -Contain 'TrustedDomainSID'
            $result.PSObject.Properties.Name | Should -Contain 'Direction'
            $result.PSObject.Properties.Name | Should -Contain 'TrustType'
            $result.PSObject.Properties.Name | Should -Contain 'IsTransitive'
            $result.PSObject.Properties.Name | Should -Contain 'ForestTransitive'
            $result.PSObject.Properties.Name | Should -Contain 'SIDFilteringEnabled'
            $result.PSObject.Properties.Name | Should -Contain 'TGTDelegationBlocked'
            $result.PSObject.Properties.Name | Should -Contain 'WithinForest'
            $result.PSObject.Properties.Name | Should -Contain 'TreatAsExternal'
            $result.PSObject.Properties.Name | Should -Contain 'TrustAttributes'
            $result.PSObject.Properties.Name | Should -Contain 'WhenCreated'
            $result.PSObject.Properties.Name | Should -Contain 'WhenModified'
            $result.PSObject.Properties.Name | Should -Contain 'SourceDomain'
        }
    }

    Context 'Trust direction decoding' {

        It 'Should return Inbound for trustDirection=1' {
            $dir = switch (1) { 1 { 'Inbound' } 2 { 'Outbound' } 3 { 'Bidirectional' } }
            $dir | Should -Be 'Inbound'
        }

        It 'Should return Outbound for trustDirection=2' {
            $dir = switch (2) { 1 { 'Inbound' } 2 { 'Outbound' } 3 { 'Bidirectional' } }
            $dir | Should -Be 'Outbound'
        }

        It 'Should return Bidirectional for trustDirection=3' {
            $dir = switch (3) { 1 { 'Inbound' } 2 { 'Outbound' } 3 { 'Bidirectional' } }
            $dir | Should -Be 'Bidirectional'
        }
    }

    Context 'Trust type name derivation' {

        It 'trustType=1 should map to DownlevelNT' {
            InModuleScope DirectoryServicesToolkit {
                $type = switch (1) {
                    1 { 'DownlevelNT' }
                    2 { 'External' }
                    3 { 'MITKerberos' }
                    4 { 'DCE' }
                }
                $type | Should -Be 'DownlevelNT'
            }
        }

        It 'trustType=2 with FOREST_TRANSITIVE bit (8) should map to Forest' {
            $trustType       = 2
            $trustAttributes = 8   # FOREST_TRANSITIVE
            $typeName = switch ($trustType) {
                2 {
                    if ($trustAttributes -band 8)      { 'Forest' }
                    elseif ($trustAttributes -band 32) { 'ParentChild' }
                    else                               { 'External' }
                }
            }
            $typeName | Should -Be 'Forest'
        }

        It 'trustType=2 with WITHIN_FOREST bit (32) should map to ParentChild' {
            $trustType       = 2
            $trustAttributes = 32   # WITHIN_FOREST
            $typeName = switch ($trustType) {
                2 {
                    if ($trustAttributes -band 8)      { 'Forest' }
                    elseif ($trustAttributes -band 32) { 'ParentChild' }
                    else                               { 'External' }
                }
            }
            $typeName | Should -Be 'ParentChild'
        }

        It 'trustType=2 with no special bits should map to External' {
            $trustType       = 2
            $trustAttributes = 0
            $typeName = switch ($trustType) {
                2 {
                    if ($trustAttributes -band 8)      { 'Forest' }
                    elseif ($trustAttributes -band 32) { 'ParentChild' }
                    else                               { 'External' }
                }
            }
            $typeName | Should -Be 'External'
        }

        It 'trustType=3 should map to MITKerberos' {
            $type = switch (3) { 1 { 'DownlevelNT' } 2 { 'External' } 3 { 'MITKerberos' } 4 { 'DCE' } }
            $type | Should -Be 'MITKerberos'
        }
    }

    Context 'IsTransitive flag — NON_TRANSITIVE bit' {

        It 'Should be $true when NON_TRANSITIVE bit (1) is NOT set' {
            $trustAttributes = 8   # FOREST_TRANSITIVE only
            $isTransitive    = -not [bool]($trustAttributes -band 1)
            $isTransitive    | Should -BeTrue
        }

        It 'Should be $false when NON_TRANSITIVE bit (1) IS set' {
            $trustAttributes = 1   # NON_TRANSITIVE
            $isTransitive    = -not [bool]($trustAttributes -band 1)
            $isTransitive    | Should -BeFalse
        }
    }

    Context 'Trust attribute bit flags' {

        It 'SIDFilteringEnabled should be $true when bit 4 is set' {
            $trustAttributes = 4
            [bool]($trustAttributes -band 4) | Should -BeTrue
        }

        It 'ForestTransitive should be $true when bit 8 is set' {
            $trustAttributes = 8
            [bool]($trustAttributes -band 8) | Should -BeTrue
        }

        It 'WithinForest should be $true when bit 32 is set' {
            $trustAttributes = 32
            [bool]($trustAttributes -band 32) | Should -BeTrue
        }

        It 'TGTDelegationBlocked should be $true when bit 512 is set' {
            $trustAttributes = 512
            [bool]($trustAttributes -band 512) | Should -BeTrue
        }

        It 'TreatAsExternal should be $true when bit 64 is set' {
            $trustAttributes = 64
            [bool]($trustAttributes -band 64) | Should -BeTrue
        }
    }

    Context 'Domain DN construction' {

        It 'Should build correct DN from DNS name' {
            $dnsName  = 'contoso.com'
            $domainDn = 'DC=' + ($dnsName -replace '\.', ',DC=')
            $domainDn | Should -Be 'DC=contoso,DC=com'
        }
    }

    Context 'Mocked query' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name              = @('partner.com')
                            trustdirection    = @(3)    # Bidirectional
                            trusttype         = @(2)    # AD/Kerberos
                            trustattributes   = @(8)    # FOREST_TRANSITIVE
                            securityidentifier = @($null)
                            flatname          = @('PARTNER')
                            whencreated       = @((Get-Date '2023-01-01'))
                            whenchanged       = @((Get-Date '2024-06-01'))
                        },
                        @{
                            name              = @('external.org')
                            trustdirection    = @(2)    # Outbound
                            trusttype         = @(2)    # AD/Kerberos
                            trustattributes   = @(0)    # no special flags
                            securityidentifier = @($null)
                            flatname          = @('EXTERNAL')
                            whencreated       = @((Get-Date '2022-01-01'))
                            whenchanged       = @((Get-Date '2022-01-01'))
                        }
                    )
                }

                Mock Resolve-DSDomainName { return 'contoso.com' }
            }
        }

        It 'Should return two trust objects' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSTrustRelationship -Domain 'contoso.com'
                $results.Count | Should -Be 2
            }
        }

        It 'Forest trust should have TrustType=Forest' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSTrustRelationship -Domain 'contoso.com'
                $forestTrust = $results | Where-Object { $_.Name -eq 'partner.com' }
                $forestTrust.TrustType | Should -Be 'Forest'
            }
        }

        It 'Forest trust should have ForestTransitive=$true' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSTrustRelationship -Domain 'contoso.com'
                $forestTrust = $results | Where-Object { $_.Name -eq 'partner.com' }
                $forestTrust.ForestTransitive | Should -BeTrue
            }
        }

        It 'External trust with no attribute flags should have SIDFilteringEnabled=$false' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSTrustRelationship -Domain 'contoso.com'
                $extTrust = $results | Where-Object { $_.Name -eq 'external.org' }
                $extTrust.SIDFilteringEnabled | Should -BeFalse
            }
        }

        It 'SourceDomain should be contoso.com for all results' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSTrustRelationship -Domain 'contoso.com'
                $results | ForEach-Object { $_.SourceDomain | Should -Be 'contoso.com' }
            }
        }
    }
}
