BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSADCSACL' -Tag 'Unit', 'Security', 'ADCS' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                CAName              = 'ContosoCA'
                CADistinguishedName = 'CN=ContosoCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                IdentityReference   = 'CONTOSO\lowprivuser'
                Rights              = 'GenericAll'
                ObjectType          = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
                Permission          = 'ManageCA'
                IsInherited         = $false
                RiskLevel           = 'High'
                Finding             = "Non-admin principal 'CONTOSO\lowprivuser' has ManageCA rights on CA 'ContosoCA' (ESC7)"
            }

            $result.PSObject.Properties.Name | Should -Contain 'CAName'
            $result.PSObject.Properties.Name | Should -Contain 'CADistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'IdentityReference'
            $result.PSObject.Properties.Name | Should -Contain 'Rights'
            $result.PSObject.Properties.Name | Should -Contain 'ObjectType'
            $result.PSObject.Properties.Name | Should -Contain 'Permission'
            $result.PSObject.Properties.Name | Should -Contain 'IsInherited'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }

        It 'RiskLevel should be High for flagged ACEs' {
            $result = [PSCustomObject]@{
                RiskLevel = 'High'
            }
            $result.RiskLevel | Should -Be 'High'
        }

        It 'Finding should contain ESC7 reference' {
            $finding = "Non-admin principal 'CONTOSO\lowprivuser' has ManageCA rights on CA 'ContosoCA' (ESC7)"
            $finding | Should -Match 'ESC7'
        }
    }

    Context 'ManageCA GUID detection' {

        It 'Should identify ManageCA from the correct GUID' {
            $manageCAGuid   = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
            $objectTypeGuid = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
            $permName       = if ($objectTypeGuid -eq $manageCAGuid) { 'ManageCA' } else { $null }
            $permName | Should -Be 'ManageCA'
        }

        It 'Should identify ManageCertificates from the correct GUID' {
            $manageCertificatesGuid = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
            $objectTypeGuid         = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
            $permName               = if ($objectTypeGuid -eq $manageCertificatesGuid) { 'ManageCertificates' } else { $null }
            $permName | Should -Be 'ManageCertificates'
        }

        It 'Should not flag unrelated GUIDs' {
            $manageCAGuid           = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
            $manageCertificatesGuid = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
            $objectTypeGuid         = '00000000-0000-0000-0000-000000000000'
            $permName = $null
            if ($objectTypeGuid -eq $manageCAGuid) { $permName = 'ManageCA' }
            elseif ($objectTypeGuid -eq $manageCertificatesGuid) { $permName = 'ManageCertificates' }
            $permName | Should -BeNullOrEmpty
        }
    }

    Context 'Safe principal exclusion' {

        It 'Should exclude Domain Admins from flagging' {
            $safePrincipals = @(
                'S-1-5-18'
                'S-1-5-32-544'
                'Enterprise Admins'
                'Domain Admins'
                'Administrators'
                'BUILTIN\Administrators'
                'NT AUTHORITY\SYSTEM'
            )
            $identity = 'CONTOSO\Domain Admins'
            $isSafe   = $false
            foreach ($safe in $safePrincipals)
            {
                if ($identity -like "*$safe*" -or $identity -eq $safe)
                {
                    $isSafe = $true
                    break
                }
            }
            $isSafe | Should -BeTrue
        }

        It 'Should flag non-administrative principals' {
            $safePrincipals = @(
                'S-1-5-18'
                'S-1-5-32-544'
                'Enterprise Admins'
                'Domain Admins'
                'Administrators'
                'BUILTIN\Administrators'
                'NT AUTHORITY\SYSTEM'
            )
            $identity = 'CONTOSO\lowprivuser'
            $isSafe   = $false
            foreach ($safe in $safePrincipals)
            {
                if ($identity -like "*$safe*" -or $identity -eq $safe)
                {
                    $isSafe = $true
                    break
                }
            }
            $isSafe | Should -BeFalse
        }
    }

    Context 'Mocked query — ACL enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name              = @('ContosoCA')
                            distinguishedname = @('CN=ContosoCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com')
                        }
                    )
                }
                Mock Get-DSObjectAcl {
                    return @(
                        [PSCustomObject]@{
                            IdentityReference     = 'CONTOSO\lowprivuser'
                            ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                            AccessControlType     = 'Allow'
                            ObjectType            = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
                            InheritanceType       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                            IsInherited           = $false
                        }
                    )
                }
            }
        }

        It 'Should return one flagged ACE for a non-admin principal with ManageCA rights' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Test-DSADCSACL -Domain 'contoso.com'
                $results.Count | Should -Be 1
            }
        }

        It 'Should set Permission to ManageCA for the ManageCA GUID' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Test-DSADCSACL -Domain 'contoso.com'
                $results[0].Permission | Should -Be 'ManageCA'
            }
        }

        It 'Should include ESC7 in the Finding for flagged ACEs' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Test-DSADCSACL -Domain 'contoso.com'
                $results[0].Finding | Should -Match 'ESC7'
            }
        }

        It 'Should set RiskLevel to High for flagged ACEs' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Test-DSADCSACL -Domain 'contoso.com'
                $results[0].RiskLevel | Should -Be 'High'
            }
        }
    }
}
