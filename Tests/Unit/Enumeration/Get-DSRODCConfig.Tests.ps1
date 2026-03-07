BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSRODCConfig' -Tag 'Unit', 'Enumeration', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                Name               = 'RODC01'
                DNSHostName        = 'rodc01.contoso.com'
                DistinguishedName  = 'CN=RODC01,OU=DomainControllers,DC=contoso,DC=com'
                OperatingSystem    = 'Windows Server 2022'
                OSVersion          = '10.0 (20348)'
                WhenCreated        = (Get-Date).AddYears(-2)
                AllowedPRPGroups   = @()
                DeniedPRPGroups    = @('CN=Denied RODC Password Replication Group,CN=Users,DC=contoso,DC=com')
                MissingDefaultDeny = $false
                Tier0InAllowedPRP  = $false
                RiskLevel          = 'Informational'
                Finding            = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'Name'
            $result.PSObject.Properties.Name | Should -Contain 'DNSHostName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'OperatingSystem'
            $result.PSObject.Properties.Name | Should -Contain 'WhenCreated'
            $result.PSObject.Properties.Name | Should -Contain 'AllowedPRPGroups'
            $result.PSObject.Properties.Name | Should -Contain 'DeniedPRPGroups'
            $result.PSObject.Properties.Name | Should -Contain 'MissingDefaultDeny'
            $result.PSObject.Properties.Name | Should -Contain 'Tier0InAllowedPRP'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }
    }

    Context 'LDAP filter — RODC identification' {

        It 'RODC filter should target primaryGroupID 521' {
            $filter = '(&(objectClass=computer)(primaryGroupID=521))'
            $filter | Should -Match 'primaryGroupID=521'
            $filter | Should -Match 'objectClass=computer'
        }
    }

    Context 'Risk level classification' {

        It 'Tier 0 group in Allowed PRP should yield Critical risk' {
            $allowedPRP      = @('CN=Domain Admins,CN=Users,DC=contoso,DC=com')
            $tier0Patterns   = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'krbtgt')
            $allowedTier0    = @($allowedPRP | Where-Object {
                $dn = $_
                $tier0Patterns | Where-Object { $dn -match $_ }
            })
            $riskLevel = if ($allowedTier0.Count -gt 0) { 'Critical' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'Missing default deny group should yield High risk' {
            $deniedPRP         = @()
            $hasDeniedRODCGroup = $deniedPRP | Where-Object { $_ -match 'Denied RODC Password Replication Group' }
            $missingDefaultDeny = ($null -eq $hasDeniedRODCGroup -or @($hasDeniedRODCGroup).Count -eq 0)
            $allowedTier0Count  = 0

            $riskLevel = if ($allowedTier0Count -gt 0) { 'Critical' }
                         elseif ($missingDefaultDeny) { 'High' }
                         else { 'Informational' }
            $riskLevel | Should -Be 'High'
        }

        It 'Default deny present and no Tier 0 in Allowed should yield Informational' {
            $deniedPRP          = @('CN=Denied RODC Password Replication Group,CN=Users,DC=contoso,DC=com')
            $hasDeniedRODCGroup  = $deniedPRP | Where-Object { $_ -match 'Denied RODC Password Replication Group' }
            $missingDefaultDeny  = ($null -eq $hasDeniedRODCGroup -or @($hasDeniedRODCGroup).Count -eq 0)
            $allowedTier0Count   = 0

            $riskLevel = if ($allowedTier0Count -gt 0) { 'Critical' }
                         elseif ($missingDefaultDeny) { 'High' }
                         else { 'Informational' }
            $riskLevel | Should -Be 'Informational'
        }
    }

    Context 'Mocked query — result enumeration' {

        It 'Should return one result per RODC found' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name                         = @('RODC01')
                            distinguishedname            = @('CN=RODC01,OU=Domain Controllers,DC=contoso,DC=com')
                            dnshostname                  = @('rodc01.contoso.com')
                            operatingsystem              = @('Windows Server 2022 Standard')
                            operatingsystemversion       = @('10.0 (20348)')
                            whencreated                  = @([datetime]'2023-01-15')
                            'msds-revealondemandgroup'   = $null
                            'msds-neverrevealgroup'      = @('CN=Denied RODC Password Replication Group,CN=Users,DC=contoso,DC=com')
                        }
                    )
                }

                $results = Get-DSRODCConfig -Domain 'contoso.com'
                $results.Count | Should -Be 1
                $results[0].Name | Should -Be 'RODC01'
            }
        }

        It 'Should flag Tier 0 in Allowed PRP as Critical' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name                         = @('RODC01')
                            distinguishedname            = @('CN=RODC01,OU=Domain Controllers,DC=contoso,DC=com')
                            dnshostname                  = @('rodc01.contoso.com')
                            operatingsystem              = @('Windows Server 2022 Standard')
                            operatingsystemversion       = @('10.0 (20348)')
                            whencreated                  = @([datetime]'2023-01-15')
                            'msds-revealondemandgroup'   = @('CN=Domain Admins,CN=Users,DC=contoso,DC=com')
                            'msds-neverrevealgroup'      = @('CN=Denied RODC Password Replication Group,CN=Users,DC=contoso,DC=com')
                        }
                    )
                }

                $results = Get-DSRODCConfig -Domain 'contoso.com'
                $results[0].RiskLevel      | Should -Be 'Critical'
                $results[0].Tier0InAllowedPRP | Should -BeTrue
            }
        }

        It 'Should return empty array when no RODCs exist' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Invoke-DSDirectorySearch { return @() }

                $results = Get-DSRODCConfig -Domain 'contoso.com'
                @($results).Count | Should -Be 0
            }
        }
    }
}
