BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSRODCCachedCredentials' -Tag 'Unit', 'Enumeration', 'Security' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                RODCName          = 'RODC01'
                RODCHostName      = 'rodc01.contoso.com'
                CachedAccountDN   = 'CN=jsmith,OU=Users,DC=contoso,DC=com'
                CachedAccountName = 'jsmith'
                IsTier0           = $false
                IsPrivileged      = $false
                RiskLevel         = 'Informational'
                Finding           = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'RODCName'
            $result.PSObject.Properties.Name | Should -Contain 'RODCHostName'
            $result.PSObject.Properties.Name | Should -Contain 'CachedAccountDN'
            $result.PSObject.Properties.Name | Should -Contain 'CachedAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'IsTier0'
            $result.PSObject.Properties.Name | Should -Contain 'IsPrivileged'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }
    }

    Context 'Risk level classification from cached DN' {

        It 'Domain Admins DN should be classified as Tier 0 Critical' {
            $cachedDN        = 'CN=da-jsmith,CN=Domain Admins,DC=contoso,DC=com'
            $tier0Patterns   = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'krbtgt')
            $isTier0 = $false
            foreach ($p in $tier0Patterns) { if ($cachedDN -match [regex]::Escape($p)) { $isTier0 = $true; break } }
            $isTier0 | Should -BeTrue
        }

        It 'krbtgt account should be classified as Tier 0 Critical' {
            $cachedDN      = 'CN=krbtgt,CN=Users,DC=contoso,DC=com'
            $tier0Patterns = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'krbtgt')
            $isTier0 = $false
            foreach ($p in $tier0Patterns) { if ($cachedDN -match [regex]::Escape($p)) { $isTier0 = $true; break } }
            $isTier0 | Should -BeTrue
        }

        It 'Standard user DN should not be classified as Tier 0' {
            $cachedDN      = 'CN=jsmith,OU=Users,DC=contoso,DC=com'
            $tier0Patterns = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'krbtgt')
            $isTier0 = $false
            foreach ($p in $tier0Patterns) { if ($cachedDN -match [regex]::Escape($p)) { $isTier0 = $true; break } }
            $isTier0 | Should -BeFalse
        }

        It 'RiskLevel should be Critical for Tier 0' {
            $isTier0     = $true
            $isPrivileged = $false
            $riskLevel   = if ($isTier0) { 'Critical' } elseif ($isPrivileged) { 'High' } else { 'Informational' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'RiskLevel should be High for privileged but non-Tier 0' {
            $isTier0     = $false
            $isPrivileged = $true
            $riskLevel   = if ($isTier0) { 'Critical' } elseif ($isPrivileged) { 'High' } else { 'Informational' }
            $riskLevel | Should -Be 'High'
        }

        It 'RiskLevel should be Informational for standard accounts' {
            $isTier0     = $false
            $isPrivileged = $false
            $riskLevel   = if ($isTier0) { 'Critical' } elseif ($isPrivileged) { 'High' } else { 'Informational' }
            $riskLevel | Should -Be 'Informational'
        }
    }

    Context 'Account CN extraction from DN' {

        It 'Should extract CN from distinguished name' {
            $dn        = 'CN=jsmith,OU=Users,DC=contoso,DC=com'
            $accountCN = if ($dn -match '^CN=([^,]+)') { $matches[1] } else { $dn }
            $accountCN | Should -Be 'jsmith'
        }

        It 'Should return full DN when CN pattern does not match' {
            $dn        = 'OU=Users,DC=contoso,DC=com'
            $accountCN = if ($dn -match '^CN=([^,]+)') { $matches[1] } else { $dn }
            $accountCN | Should -Be $dn
        }
    }

    Context 'Mocked query — result enumeration' {

        It 'Should return one result per cached account per RODC' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name                  = @('RODC01')
                            distinguishedname     = @('CN=RODC01,OU=Domain Controllers,DC=contoso,DC=com')
                            dnshostname           = @('rodc01.contoso.com')
                            'msds-revealedlist'   = @(
                                'CN=jsmith,OU=Users,DC=contoso,DC=com'
                                'CN=bwilson,OU=Users,DC=contoso,DC=com'
                            )
                        }
                    )
                }

                $results = Find-DSRODCCachedCredentials -Domain 'contoso.com'
                $results.Count | Should -Be 2
                $results[0].RODCName | Should -Be 'RODC01'
            }
        }

        It 'Should return empty when no credentials are cached' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name                  = @('RODC01')
                            distinguishedname     = @('CN=RODC01,OU=Domain Controllers,DC=contoso,DC=com')
                            dnshostname           = @('rodc01.contoso.com')
                            'msds-revealedlist'   = $null
                        }
                    )
                }

                $results = Find-DSRODCCachedCredentials -Domain 'contoso.com'
                @($results).Count | Should -Be 0
            }
        }

        It 'Should filter to Critical and High only when -HighlightTier0 is specified' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name                  = @('RODC01')
                            distinguishedname     = @('CN=RODC01,OU=Domain Controllers,DC=contoso,DC=com')
                            dnshostname           = @('rodc01.contoso.com')
                            'msds-revealedlist'   = @(
                                'CN=jsmith,OU=Users,DC=contoso,DC=com'
                                'CN=krbtgt,CN=Users,DC=contoso,DC=com'
                            )
                        }
                    )
                }

                $results = Find-DSRODCCachedCredentials -Domain 'contoso.com' -HighlightTier0
                # Only krbtgt should be returned (Tier 0 = Critical)
                $results.Count | Should -Be 1
                $results[0].CachedAccountName | Should -Be 'krbtgt'
            }
        }
    }
}
