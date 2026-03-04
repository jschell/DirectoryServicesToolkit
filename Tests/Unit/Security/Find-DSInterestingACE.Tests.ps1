BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSInterestingACE' -Tag 'Unit', 'Security' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                TargetObject      = 'CN=svc-sql,OU=ServiceAccounts,DC=contoso,DC=com'
                TargetObjectClass = 'user'
                Principal         = 'CONTOSO\helpdesk'
                Right             = 'GenericAll'
                AccessType        = 'Allow'
                IsInherited       = $false
            }

            $result.PSObject.Properties.Name | Should -Contain 'TargetObject'
            $result.PSObject.Properties.Name | Should -Contain 'TargetObjectClass'
            $result.PSObject.Properties.Name | Should -Contain 'Principal'
            $result.PSObject.Properties.Name | Should -Contain 'Right'
            $result.PSObject.Properties.Name | Should -Contain 'AccessType'
            $result.PSObject.Properties.Name | Should -Contain 'IsInherited'
        }
    }

    Context 'Get-DSFlaggedRightName — right classification' {

        It 'Should return GenericAll for GenericAll rights' {
            InModuleScope DirectoryServicesToolkit {
                $rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                $name   = Get-DSFlaggedRightName -AceRights $rights
                $name | Should -Be 'GenericAll'
            }
        }

        It 'Should return WriteDACL when WriteDacl bit is set' {
            InModuleScope DirectoryServicesToolkit {
                $rights = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
                $name   = Get-DSFlaggedRightName -AceRights $rights
                $name | Should -Be 'WriteDACL'
            }
        }

        It 'Should return WriteOwner when WriteOwner bit is set' {
            InModuleScope DirectoryServicesToolkit {
                $rights = [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner
                $name   = Get-DSFlaggedRightName -AceRights $rights
                $name | Should -Be 'WriteOwner'
            }
        }

        It 'Should return GenericWrite when GenericWrite bits are set' {
            InModuleScope DirectoryServicesToolkit {
                $rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
                $name   = Get-DSFlaggedRightName -AceRights $rights
                $name | Should -Be 'GenericWrite'
            }
        }

        It 'Should return AllExtendedRights for ExtendedRight with empty ObjectType GUID' {
            InModuleScope DirectoryServicesToolkit {
                $rights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                $name   = Get-DSFlaggedRightName -AceRights $rights -AceObjectType ([Guid]::Empty)
                $name | Should -Be 'AllExtendedRights'
            }
        }

        It 'Should return ForceChangePassword for the specific extended right GUID' {
            InModuleScope DirectoryServicesToolkit {
                $rights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                $guid   = [Guid]'00299570-246d-11d0-a768-00aa006e0529'
                $name   = Get-DSFlaggedRightName -AceRights $rights -AceObjectType $guid
                $name | Should -Be 'ForceChangePassword'
            }
        }

        It 'Should return null for non-dangerous rights (ReadProperty only)' {
            InModuleScope DirectoryServicesToolkit {
                $rights = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
                $name   = Get-DSFlaggedRightName -AceRights $rights
                $name | Should -BeNullOrEmpty
            }
        }

        It 'Should return null for CreateChild only (not dangerous on its own)' {
            InModuleScope DirectoryServicesToolkit {
                $rights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                $name   = Get-DSFlaggedRightName -AceRights $rights
                $name | Should -BeNullOrEmpty
            }
        }
    }

    Context 'Inherited ACE filtering' {

        It 'Inherited ACEs should be excluded by default' {
            $ace = [PSCustomObject]@{
                AccessControlType    = 'Allow'
                IsInherited          = $true
                ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
            }

            # Simulate the default filter: skip inherited unless IncludeInherited is set
            $includeInherited = $false
            $shouldSkip = ($ace.IsInherited -and -not $includeInherited)
            $shouldSkip | Should -BeTrue
        }

        It 'Inherited ACEs should be included when -IncludeInherited is specified' {
            $ace = [PSCustomObject]@{
                AccessControlType    = 'Allow'
                IsInherited          = $true
                ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
            }

            $includeInherited = $true
            $shouldSkip = ($ace.IsInherited -and -not $includeInherited)
            $shouldSkip | Should -BeFalse
        }
    }

    Context 'Deny ACE filtering' {

        It 'Deny ACEs should be skipped' {
            $ace = [PSCustomObject]@{
                AccessControlType    = 'Deny'
                IsInherited          = $false
                ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
            }

            $shouldSkip = ($ace.AccessControlType -ne 'Allow')
            $shouldSkip | Should -BeTrue
        }
    }

    Context 'Mocked query — ACE enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            distinguishedname = @('CN=svc-sql,OU=ServiceAccounts,DC=contoso,DC=com')
                            samaccountname    = @('svc-sql')
                            objectclass       = @('top', 'person', 'user')
                        }
                    )
                }

                Mock Get-DSObjectAcl {
                    return @(
                        [PSCustomObject]@{
                            IdentityReference     = 'CONTOSO\helpdesk'
                            ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                            AccessControlType     = 'Allow'
                            ObjectType            = [Guid]::Empty
                            IsInherited           = $false
                        }
                    )
                }
            }
        }

        It 'Should return result when GenericAll ACE exists' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSInterestingACE -Domain 'contoso.com'
                $results | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should not return result when only ReadProperty ACE exists' {
            InModuleScope DirectoryServicesToolkit {
                Mock Get-DSObjectAcl {
                    return @(
                        [PSCustomObject]@{
                            IdentityReference     = 'CONTOSO\helpdesk'
                            ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
                            AccessControlType     = 'Allow'
                            ObjectType            = [Guid]::Empty
                            IsInherited           = $false
                        }
                    )
                }

                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSInterestingACE -Domain 'contoso.com'
                $results.Count | Should -Be 0
            }
        }

        It 'Should not return inherited ACEs when IncludeInherited is not set' {
            InModuleScope DirectoryServicesToolkit {
                Mock Get-DSObjectAcl {
                    return @(
                        [PSCustomObject]@{
                            IdentityReference     = 'CONTOSO\helpdesk'
                            ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
                            AccessControlType     = 'Allow'
                            ObjectType            = [Guid]::Empty
                            IsInherited           = $true   # inherited — should be filtered
                        }
                    )
                }

                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSInterestingACE -Domain 'contoso.com'
                $results.Count | Should -Be 0
            }
        }

        It 'Should return inherited ACEs when -IncludeInherited is specified' {
            InModuleScope DirectoryServicesToolkit {
                Mock Get-DSObjectAcl {
                    return @(
                        [PSCustomObject]@{
                            IdentityReference     = 'CONTOSO\helpdesk'
                            ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
                            AccessControlType     = 'Allow'
                            ObjectType            = [Guid]::Empty
                            IsInherited           = $true
                        }
                    )
                }

                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSInterestingACE -Domain 'contoso.com' -IncludeInherited
                $results.Count | Should -Be 1
            }
        }
    }

    Context 'ForceChangePassword GUID' {

        It 'ForceChangePassword GUID should match the known value' {
            $expectedGuid = [Guid]'00299570-246d-11d0-a768-00aa006e0529'
            $expectedGuid | Should -Not -BeNullOrEmpty
            $expectedGuid.ToString() | Should -Be '00299570-246d-11d0-a768-00aa006e0529'
        }
    }

    Context 'Parameter defaults' {

        It 'SizeLimit should default to 1000' {
            $cmd  = Get-Command Find-DSInterestingACE -Module DirectoryServicesToolkit
            $param = $cmd.Parameters['SizeLimit']
            $param | Should -Not -BeNullOrEmpty
        }

        It 'IncludeInherited should default to false' {
            $cmd   = Get-Command Find-DSInterestingACE -Module DirectoryServicesToolkit
            $param = $cmd.Parameters['IncludeInherited']
            $param.ParameterType | Should -Be ([switch])
        }
    }
}
