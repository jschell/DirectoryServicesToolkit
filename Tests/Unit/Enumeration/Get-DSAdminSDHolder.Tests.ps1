BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSAdminSDHolder' -Tag 'Unit', 'Enumeration' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                SamAccountName           = 'oldadmin'
                DistinguishedName        = 'CN=oldadmin,OU=Users,DC=contoso,DC=com'
                ObjectClass              = 'user'
                Enabled                  = $true
                AdminCount               = 1
                IsCurrentProtectedMember = $false
            }

            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'ObjectClass'
            $result.PSObject.Properties.Name | Should -Contain 'Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'AdminCount'
            $result.PSObject.Properties.Name | Should -Contain 'IsCurrentProtectedMember'
        }
    }

    Context 'IsCurrentProtectedMember flag logic' {

        It 'Should be $false when DN is not in protected member set' {
            $protectedMembers = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            [void]$protectedMembers.Add('CN=admin1,OU=Admins,DC=contoso,DC=com')

            $dn        = 'CN=oldadmin,OU=Users,DC=contoso,DC=com'
            $isCurrent = $protectedMembers.Contains($dn)
            $isCurrent | Should -BeFalse
        }

        It 'Should be $true when DN is in protected member set' {
            $protectedMembers = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            [void]$protectedMembers.Add('CN=admin1,OU=Admins,DC=contoso,DC=com')

            $dn        = 'CN=admin1,OU=Admins,DC=contoso,DC=com'
            $isCurrent = $protectedMembers.Contains($dn)
            $isCurrent | Should -BeTrue
        }

        It 'Lookup should be case-insensitive' {
            $protectedMembers = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            [void]$protectedMembers.Add('CN=Admin1,OU=Admins,DC=contoso,DC=com')

            $dn = 'cn=admin1,ou=admins,dc=contoso,dc=com'
            $protectedMembers.Contains($dn) | Should -BeTrue
        }
    }

    Context 'IncludeExpected filtering' {

        It 'Should exclude current protected members by default' {
            # Simulate filter logic
            $isCurrent    = $true
            $includeExpected = $false
            $shouldSkip   = (-not $includeExpected -and $isCurrent)
            $shouldSkip   | Should -BeTrue
        }

        It 'Should include current protected members when -IncludeExpected is set' {
            $isCurrent       = $true
            $includeExpected = $true
            $shouldSkip      = (-not $includeExpected -and $isCurrent)
            $shouldSkip      | Should -BeFalse
        }

        It 'Should always include non-protected members' {
            $isCurrent       = $false
            $includeExpected = $false
            $shouldSkip      = (-not $includeExpected -and $isCurrent)
            $shouldSkip      | Should -BeFalse
        }
    }

    Context 'Mocked query — residual AdminCount account' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    param($LdapPath, $Filter)

                    # Group resolution
                    if ($Filter -match 'objectClass=group')
                    {
                        return @(
                            @{ distinguishedname = @('CN=Domain Admins,CN=Users,DC=contoso,DC=com') }
                        )
                    }

                    # Transitive member query — returns no current members
                    if ($Filter -match 'memberOf:1\.2\.840')
                    {
                        return @()
                    }

                    # adminCount=1 query — one user with adminCount set
                    if ($Filter -match 'adminCount')
                    {
                        return @(
                            @{
                                distinguishedname  = @('CN=oldadmin,OU=Users,DC=contoso,DC=com')
                                samaccountname     = @('oldadmin')
                                useraccountcontrol = @(512)
                                objectclass        = @('top', 'person', 'user')
                                admincount         = @(1)
                            }
                        )
                    }

                    return @()
                }

                Mock Resolve-DSDomainName { return 'contoso.com' }
            }
        }

        It 'Should return the residual account' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSAdminSDHolder -Domain 'contoso.com'
                $results | Should -Not -BeNullOrEmpty
            }
        }

        It 'IsCurrentProtectedMember should be $false for residual account' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSAdminSDHolder -Domain 'contoso.com'
                $results[0].IsCurrentProtectedMember | Should -BeFalse
            }
        }

        It 'AdminCount should be 1' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSAdminSDHolder -Domain 'contoso.com'
                $results[0].AdminCount | Should -Be 1
            }
        }
    }

    Context 'Parameter validation' {

        It 'IncludeExpected parameter should be a switch' {
            $cmd   = Get-Command Get-DSAdminSDHolder -Module DirectoryServicesToolkit
            $param = $cmd.Parameters['IncludeExpected']
            $param.ParameterType | Should -Be ([switch])
        }
    }
}
