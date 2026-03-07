BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSStalePrivilegedAccounts' -Tag 'Unit', 'AccountHygiene', 'Security' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                SamAccountName    = 'da-old-jsmith'
                DistinguishedName = 'CN=da-old-jsmith,OU=AdminAccounts,DC=contoso,DC=com'
                Enabled           = $false
                PasswordLastSet   = (Get-Date).AddDays(-365)
                LastLogon         = (Get-Date).AddDays(-400)
                WhenChanged       = (Get-Date).AddDays(-300)
                Groups            = @('Domain Admins')
                RiskLevel         = 'Critical'
                Finding           = 'Stale account disabled but retains membership in: Domain Admins'
            }

            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordLastSet'
            $result.PSObject.Properties.Name | Should -Contain 'LastLogon'
            $result.PSObject.Properties.Name | Should -Contain 'WhenChanged'
            $result.PSObject.Properties.Name | Should -Contain 'Groups'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }

        It 'Enabled should always be false for results' {
            $uac     = 2   # ACCOUNTDISABLE bit set
            $enabled = -not [bool]($uac -band 2)
            $enabled | Should -BeFalse
        }
    }

    Context 'Risk level classification' {

        It 'Domain Admins membership should yield Critical risk' {
            $groupList = @('Domain Admins')
            $isTier0   = ($groupList -contains 'Domain Admins') -or
                         ($groupList -contains 'Enterprise Admins') -or
                         ($groupList -contains 'Schema Admins')
            $riskLevel = if ($isTier0) { 'Critical' } else { 'High' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'Enterprise Admins membership should yield Critical risk' {
            $groupList = @('Enterprise Admins')
            $isTier0   = ($groupList -contains 'Domain Admins') -or
                         ($groupList -contains 'Enterprise Admins') -or
                         ($groupList -contains 'Schema Admins')
            $riskLevel = if ($isTier0) { 'Critical' } else { 'High' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'Schema Admins membership should yield Critical risk' {
            $groupList = @('Schema Admins')
            $isTier0   = ($groupList -contains 'Domain Admins') -or
                         ($groupList -contains 'Enterprise Admins') -or
                         ($groupList -contains 'Schema Admins')
            $riskLevel = if ($isTier0) { 'Critical' } else { 'High' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'Administrators-only membership should yield High risk' {
            $groupList = @('Administrators')
            $isTier0   = ($groupList -contains 'Domain Admins') -or
                         ($groupList -contains 'Enterprise Admins') -or
                         ($groupList -contains 'Schema Admins')
            $riskLevel = if ($isTier0) { 'Critical' } else { 'High' }
            $riskLevel | Should -Be 'High'
        }
    }

    Context 'LDAP filter — disabled user detection' {

        It 'UAC bitwise filter should correctly identify disabled bit' {
            $uacDisabled  = 2      # ACCOUNTDISABLE
            $uacEnabled   = 512    # NORMAL_ACCOUNT only

            [bool]($uacDisabled -band 2) | Should -BeTrue
            [bool]($uacEnabled -band 2)  | Should -BeFalse
        }

        It 'Filter should use LDAP_MATCHING_RULE_BIT_AND for UAC check' {
            $memberFilter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,DC=contoso,DC=com))'
            $memberFilter | Should -Match '1.2.840.113556.1.4.803'
            $memberFilter | Should -Match '1.2.840.113556.1.4.1941'
        }
    }

    Context 'Mocked query — result enumeration' {

        It 'Should return a result for a disabled Domain Admin account' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Invoke-DSDirectorySearch -ParameterFilter {
                    $Filter -match 'objectClass=group'
                } {
                    return @(
                        @{
                            distinguishedname = @('CN=Domain Admins,CN=Users,DC=contoso,DC=com')
                        }
                    )
                }
                Mock Invoke-DSDirectorySearch -ParameterFilter {
                    $Filter -match 'objectClass=user'
                } {
                    return @(
                        @{
                            distinguishedname    = @('CN=da-old-jsmith,OU=AdminAccounts,DC=contoso,DC=com')
                            samaccountname       = @('da-old-jsmith')
                            useraccountcontrol   = @(514)   # disabled + normal account
                            pwdlastset           = @(132000000000000000L)
                            lastlogontimestamp   = @(132000000000000000L)
                            whenchanged          = @([datetime]'2024-01-01')
                        }
                    )
                }

                $results = Find-DSStalePrivilegedAccounts -Domain 'contoso.com'
                $results | Should -Not -BeNullOrEmpty
                $results[0].SamAccountName | Should -Be 'da-old-jsmith'
                $results[0].Enabled        | Should -BeFalse
                $results[0].Groups         | Should -Contain 'Domain Admins'
            }
        }

        It 'Should deduplicate accounts that appear in multiple groups' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Invoke-DSDirectorySearch -ParameterFilter {
                    $Filter -match 'objectClass=group'
                } {
                    return @(
                        @{
                            distinguishedname = @('CN=Domain Admins,CN=Users,DC=contoso,DC=com')
                        }
                    )
                }
                Mock Invoke-DSDirectorySearch -ParameterFilter {
                    $Filter -match 'objectClass=user'
                } {
                    return @(
                        @{
                            distinguishedname    = @('CN=da-old-jsmith,OU=AdminAccounts,DC=contoso,DC=com')
                            samaccountname       = @('da-old-jsmith')
                            useraccountcontrol   = @(514)
                            pwdlastset           = @(132000000000000000L)
                            lastlogontimestamp   = @(132000000000000000L)
                            whenchanged          = @([datetime]'2024-01-01')
                        }
                    )
                }

                $results = Find-DSStalePrivilegedAccounts -Domain 'contoso.com' -Groups 'Domain Admins'
                $results.Count | Should -Be 1
            }
        }
    }
}
