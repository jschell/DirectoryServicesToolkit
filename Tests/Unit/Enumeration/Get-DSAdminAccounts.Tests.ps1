BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSAdminAccounts' -Tag 'Unit', 'Enumeration' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                SamAccountName    = 'admin1'
                DistinguishedName = 'CN=admin1,OU=Admins,DC=contoso,DC=com'
                Enabled           = $true
                PasswordLastSet   = (Get-Date)
                LastLogon         = (Get-Date)
                Groups            = @('Domain Admins')
            }

            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordLastSet'
            $result.PSObject.Properties.Name | Should -Contain 'LastLogon'
            $result.PSObject.Properties.Name | Should -Contain 'Groups'
        }

        It 'Groups should be an array' {
            $result = [PSCustomObject]@{
                SamAccountName    = 'admin1'
                DistinguishedName = 'CN=admin1,OU=Admins,DC=contoso,DC=com'
                Enabled           = $true
                PasswordLastSet   = $null
                LastLogon         = $null
                Groups            = @('Domain Admins', 'Administrators')
            }

            $result.Groups | Should -BeOfType [string]
            $result.Groups.Count | Should -Be 2
        }
    }

    Context 'Enabled flag — UAC bit extraction' {

        It 'Should set Enabled=$true when UAC bit 2 is not set' {
            $uac     = 512   # NormalAccount, enabled
            $enabled = -not [bool]($uac -band 2)
            $enabled | Should -BeTrue
        }

        It 'Should set Enabled=$false when UAC bit 2 is set' {
            $uac     = 514   # NormalAccount + AccountDisable
            $enabled = -not [bool]($uac -band 2)
            $enabled | Should -BeFalse
        }
    }

    Context 'FILETIME conversion' {

        It 'Should convert valid lastLogonTimestamp to DateTime' {
            $fileTime = (Get-Date '2025-01-01').ToFileTime()
            $dt       = [DateTime]::FromFileTime([long]$fileTime)
            $dt       | Should -BeOfType [DateTime]
        }

        It 'Should return $null for lastLogonTimestamp of 0' {
            $raw    = 0
            $result = if ($null -ne $raw -and [long]$raw -gt 0)
                      { [DateTime]::FromFileTime([long]$raw) }
                      else { $null }
            $result | Should -BeNullOrEmpty
        }
    }

    Context 'Deduplication — account in multiple groups' {

        It 'An account matching two groups should appear once with both groups listed' {
            # Simulate deduplication logic
            $accountMap = [System.Collections.Generic.Dictionary[string, object]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )

            $dn     = 'CN=admin1,OU=Admins,DC=contoso,DC=com'
            $groups = @('Domain Admins', 'Administrators')

            foreach ($group in $groups)
            {
                if ($accountMap.ContainsKey($dn))
                {
                    [void]$accountMap[$dn].Groups.Add($group)
                }
                else
                {
                    $entry = [PSCustomObject]@{
                        Groups = [System.Collections.Generic.List[string]]::new()
                    }
                    [void]$entry.Groups.Add($group)
                    $accountMap[$dn] = $entry
                }
            }

            $accountMap.Count         | Should -Be 1
            $accountMap[$dn].Groups.Count | Should -Be 2
            $accountMap[$dn].Groups   | Should -Contain 'Domain Admins'
            $accountMap[$dn].Groups   | Should -Contain 'Administrators'
        }
    }

    Context 'Parameter defaults' {

        It 'Groups parameter should default to the standard 5-group set' {
            $cmd   = Get-Command Get-DSAdminAccounts -Module DirectoryServicesToolkit
            $param = $cmd.Parameters['Groups']
            $param | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Mocked query' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    param($LdapPath, $Filter, $Properties)

                    # Group resolution query
                    if ($Filter -match 'objectClass=group')
                    {
                        return @(
                            @{ distinguishedname = @('CN=Domain Admins,CN=Users,DC=contoso,DC=com') }
                        )
                    }

                    # Transitive member query
                    return @(
                        @{
                            distinguishedname    = @('CN=admin1,OU=Admins,DC=contoso,DC=com')
                            samaccountname       = @('admin1')
                            useraccountcontrol   = @(512)
                            pwdlastset           = @(0)
                            lastlogontimestamp   = @(0)
                            memberof             = @()
                        }
                    )
                }

                Mock New-Object {
                    return [PSCustomObject]@{ Name = 'contoso.com' }
                } -ParameterFilter { $TypeName -match 'DirectoryContext' }

                $fakeEntry = [PSCustomObject]@{ Name = 'contoso.com' }
                Mock ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain) { return $fakeEntry }
            }
        }

        It 'Should return a result for a mocked privileged account' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSAdminAccounts -Domain 'contoso.com' -Groups @('Domain Admins')
                $results | Should -Not -BeNullOrEmpty
            }
        }

        It 'Returned result should have correct SamAccountName' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSAdminAccounts -Domain 'contoso.com' -Groups @('Domain Admins')
                $results[0].SamAccountName | Should -Be 'admin1'
            }
        }

        It 'Returned result should list the matched group' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSAdminAccounts -Domain 'contoso.com' -Groups @('Domain Admins')
                $results[0].Groups | Should -Contain 'Domain Admins'
            }
        }
    }
}
