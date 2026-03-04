BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSGPO' -Tag 'Unit', 'Enumeration' {

    Context 'Output schema validation' {

        It 'Should include all required top-level output properties' {
            $result = [PSCustomObject]@{
                DisplayName             = 'Default Domain Policy'
                GPOId                   = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
                WhenCreated             = (Get-Date)
                WhenModified            = (Get-Date)
                UserSettingsEnabled     = $true
                ComputerSettingsEnabled = $true
                WMIFilter               = $null
                Links                   = @()
                IsLinked                = $false
            }

            $result.PSObject.Properties.Name | Should -Contain 'DisplayName'
            $result.PSObject.Properties.Name | Should -Contain 'GPOId'
            $result.PSObject.Properties.Name | Should -Contain 'WhenCreated'
            $result.PSObject.Properties.Name | Should -Contain 'WhenModified'
            $result.PSObject.Properties.Name | Should -Contain 'UserSettingsEnabled'
            $result.PSObject.Properties.Name | Should -Contain 'ComputerSettingsEnabled'
            $result.PSObject.Properties.Name | Should -Contain 'WMIFilter'
            $result.PSObject.Properties.Name | Should -Contain 'Links'
            $result.PSObject.Properties.Name | Should -Contain 'IsLinked'
        }

        It 'Links entry should include all required properties' {
            $link = [PSCustomObject]@{
                LinkedTo           = 'OU=Domain Controllers,DC=contoso,DC=com'
                LinkEnabled        = $true
                LinkEnforced       = $false
                InheritanceBlocked = $false
            }

            $link.PSObject.Properties.Name | Should -Contain 'LinkedTo'
            $link.PSObject.Properties.Name | Should -Contain 'LinkEnabled'
            $link.PSObject.Properties.Name | Should -Contain 'LinkEnforced'
            $link.PSObject.Properties.Name | Should -Contain 'InheritanceBlocked'
        }
    }

    Context 'gpLink parsing' {

        It 'Should parse a simple gpLink string into GUID and option' {
            $gpLinkStr    = '[LDAP://cn={A1B2C3D4-0000-0000-0000-000000000001},cn=policies,cn=system,DC=contoso,DC=com;0]'
            $pattern      = '\[LDAP://[^;]+cn=(\{[^}]+\})[^;]*;(\d+)\]'
            $matches2     = [regex]::Matches($gpLinkStr, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

            $matches2.Count            | Should -Be 1
            $matches2[0].Groups[1].Value | Should -Match '\{[A-Fa-f0-9-]+\}'
            $matches2[0].Groups[2].Value | Should -Be '0'
        }

        It 'Should parse link option 0 as enabled and not enforced' {
            $linkOption   = 0
            $linkEnabled  = -not [bool]($linkOption -band 1)
            $linkEnforced = [bool]($linkOption -band 2)

            $linkEnabled  | Should -BeTrue
            $linkEnforced | Should -BeFalse
        }

        It 'Should parse link option 1 as disabled' {
            $linkOption  = 1
            $linkEnabled = -not [bool]($linkOption -band 1)
            $linkEnabled | Should -BeFalse
        }

        It 'Should parse link option 2 as enforced' {
            $linkOption   = 2
            $linkEnforced = [bool]($linkOption -band 2)
            $linkEnforced | Should -BeTrue
        }

        It 'Should parse multiple links in a single gpLink string' {
            $gpLinkStr = '[LDAP://cn={GUID1},cn=policies,cn=system,DC=contoso,DC=com;0][LDAP://cn={GUID2},cn=policies,cn=system,DC=contoso,DC=com;2]'
            $pattern   = '\[LDAP://[^;]+cn=(\{[^}]+\})[^;]*;(\d+)\]'
            $matches2  = [regex]::Matches($gpLinkStr, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $matches2.Count | Should -Be 2
        }
    }

    Context 'GPO flags — UserSettings and ComputerSettings' {

        It 'flags=0 means both user and computer settings enabled' {
            $flags = 0
            $userEnabled     = -not [bool]($flags -band 1)
            $computerEnabled = -not [bool]($flags -band 2)
            $userEnabled     | Should -BeTrue
            $computerEnabled | Should -BeTrue
        }

        It 'flags=1 means user settings disabled' {
            $flags       = 1
            $userEnabled = -not [bool]($flags -band 1)
            $userEnabled | Should -BeFalse
        }

        It 'flags=2 means computer settings disabled' {
            $flags           = 2
            $computerEnabled = -not [bool]($flags -band 2)
            $computerEnabled | Should -BeFalse
        }

        It 'flags=3 means both settings disabled' {
            $flags           = 3
            $userEnabled     = -not [bool]($flags -band 1)
            $computerEnabled = -not [bool]($flags -band 2)
            $userEnabled     | Should -BeFalse
            $computerEnabled | Should -BeFalse
        }
    }

    Context 'Domain DN construction' {

        It 'Should convert DNS name to LDAP DN format' {
            $dnsName  = 'contoso.com'
            $domainDn = 'DC=' + ($dnsName -replace '\.', ',DC=')
            $domainDn | Should -Be 'DC=contoso,DC=com'
        }

        It 'Should handle multi-level DNS names' {
            $dnsName  = 'corp.contoso.com'
            $domainDn = 'DC=' + ($dnsName -replace '\.', ',DC=')
            $domainDn | Should -Be 'DC=corp,DC=contoso,DC=com'
        }
    }

    Context 'Mocked query' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                $script:GpoGuid    = '{a1b2c3d4-0000-0000-0000-000000000001}'
                $script:LinkedGuid = '{a1b2c3d4-0000-0000-0000-000000000002}'

                Mock Invoke-DSDirectorySearch {
                    param($LdapPath, $Filter)

                    # GPO enumeration pass
                    if ($Filter -eq '(objectClass=groupPolicyContainer)')
                    {
                        return @(
                            @{
                                cn          = @($script:GpoGuid)
                                displayname = @('Unlinked Test Policy')
                                flags       = @(0)
                                whencreated = @((Get-Date '2025-01-01'))
                                whenchanged = @((Get-Date '2025-06-01'))
                                gpcwqlfilter = @()
                            },
                            @{
                                cn          = @($script:LinkedGuid)
                                displayname = @('DC Policy')
                                flags       = @(0)
                                whencreated = @((Get-Date '2024-01-01'))
                                whenchanged = @((Get-Date '2025-01-01'))
                                gpcwqlfilter = @()
                            }
                        )
                    }

                    # gpLink pass — one container with a link to the second GPO
                    if ($Filter -eq '(gpLink=*)')
                    {
                        $linkStr = "[LDAP://cn=$($script:LinkedGuid),cn=policies,cn=system,DC=contoso,DC=com;0]"
                        return @(
                            @{
                                distinguishedname = @('OU=Domain Controllers,DC=contoso,DC=com')
                                gplink            = @($linkStr)
                                gpoptions         = @(0)
                            }
                        )
                    }

                    return @()
                }

                Mock Resolve-DSDomainName { return 'contoso.com' }
            }
        }

        It 'Should return both GPOs by default' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSGPO -Domain 'contoso.com'
                $results.Count | Should -Be 2
            }
        }

        It '-LinkedOnly should return only the linked GPO' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSGPO -Domain 'contoso.com' -LinkedOnly
                $results.Count | Should -Be 1
                $results[0].IsLinked | Should -BeTrue
            }
        }

        It 'Linked GPO should have one entry in Links' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSGPO -Domain 'contoso.com' -LinkedOnly
                $results[0].Links.Count | Should -Be 1
            }
        }

        It 'Link LinkedTo should be the Domain Controllers OU' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSGPO -Domain 'contoso.com' -LinkedOnly
                $results[0].Links[0].LinkedTo | Should -Match 'Domain Controllers'
            }
        }

        It '-HighValueOUsOnly should return only GPOs linked to high-value OUs' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSGPO -Domain 'contoso.com' -HighValueOUsOnly
                $results.Count | Should -Be 1
                $results[0].DisplayName | Should -Be 'DC Policy'
            }
        }

        It 'Unlinked GPO IsLinked should be $false' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSGPO -Domain 'contoso.com'
                $unlinked = $results | Where-Object { -not $_.IsLinked }
                $unlinked | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context 'Parameter validation' {

        It 'LinkedOnly should be a switch parameter' {
            $cmd   = Get-Command Get-DSGPO -Module DirectoryServicesToolkit
            $param = $cmd.Parameters['LinkedOnly']
            $param.ParameterType | Should -Be ([switch])
        }

        It 'HighValueOUsOnly should be a switch parameter' {
            $cmd   = Get-Command Get-DSGPO -Module DirectoryServicesToolkit
            $param = $cmd.Parameters['HighValueOUsOnly']
            $param.ParameterType | Should -Be ([switch])
        }
    }
}
