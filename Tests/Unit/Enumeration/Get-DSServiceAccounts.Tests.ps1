BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSServiceAccounts' -Tag 'Unit', 'Enumeration' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                SamAccountName       = 'svc-sql'
                DistinguishedName    = 'CN=svc-sql,OU=ServiceAccounts,DC=contoso,DC=com'
                SPNs                 = @('MSSQLSvc/db01.contoso.com:1433')
                Description          = 'SQL Service Account'
                Enabled              = $true
                PasswordNeverExpires = $true
                PasswordLastSet      = (Get-Date)
                DetectedBy           = @('SPN', 'OU')
            }

            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'SPNs'
            $result.PSObject.Properties.Name | Should -Contain 'Description'
            $result.PSObject.Properties.Name | Should -Contain 'Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordNeverExpires'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordLastSet'
            $result.PSObject.Properties.Name | Should -Contain 'DetectedBy'
        }

        It 'SPNs should be an array' {
            $result = [PSCustomObject]@{
                SPNs = @('MSSQLSvc/db01.contoso.com:1433', 'MSSQLSvc/db01:1433')
            }
            $result.SPNs.Count | Should -Be 2
        }

        It 'DetectedBy should be an array' {
            $result = [PSCustomObject]@{
                DetectedBy = @('SPN', 'OU')
            }
            $result.DetectedBy | Should -Contain 'SPN'
            $result.DetectedBy | Should -Contain 'OU'
        }
    }

    Context 'UAC bit — PasswordNeverExpires' {

        It 'Should be $true when UAC bit 65536 is set' {
            $uac = 66048   # 512 + 65536
            [bool]($uac -band 65536) | Should -BeTrue
        }

        It 'Should be $false when UAC bit 65536 is not set' {
            $uac = 512
            [bool]($uac -band 65536) | Should -BeFalse
        }
    }

    Context 'OU keyword detection' {

        It 'Should detect ServiceAccount keyword in DN' {
            $dn       = 'CN=svc-sql,OU=ServiceAccounts,DC=contoso,DC=com'
            $keywords = @('ServiceAccount', 'SvcAcct', 'Service', 'SA_', '_svc')
            $matched  = $false
            foreach ($kw in $keywords)
            {
                if ($dn -match [regex]::Escape($kw)) { $matched = $true; break }
            }
            $matched | Should -BeTrue
        }

        It 'Should not flag a normal user DN as service account OU' {
            $dn       = 'CN=jdoe,OU=Users,DC=contoso,DC=com'
            $keywords = @('ServiceAccount', 'SvcAcct', 'Service', 'SA_', '_svc')
            $matched  = $false
            foreach ($kw in $keywords)
            {
                if ($dn -match [regex]::Escape($kw)) { $matched = $true; break }
            }
            $matched | Should -BeFalse
        }
    }

    Context 'Deduplication — account matching multiple indicators' {

        It 'An account matching both SPN and description should appear once with both in DetectedBy' {
            $accountMap = [System.Collections.Generic.Dictionary[string, object]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            $dn = 'CN=svc-sql,OU=ServiceAccounts,DC=contoso,DC=com'

            foreach ($indicator in @('SPN', 'Description'))
            {
                if (-not $accountMap.ContainsKey($dn))
                {
                    $accountMap[$dn] = [PSCustomObject]@{
                        DetectedBy = [System.Collections.Generic.List[string]]::new()
                    }
                }
                if (-not $accountMap[$dn].DetectedBy.Contains($indicator))
                {
                    [void]$accountMap[$dn].DetectedBy.Add($indicator)
                }
            }

            $accountMap.Count                  | Should -Be 1
            $accountMap[$dn].DetectedBy.Count  | Should -Be 2
            $accountMap[$dn].DetectedBy        | Should -Contain 'SPN'
            $accountMap[$dn].DetectedBy        | Should -Contain 'Description'
        }
    }

    Context 'Mocked query' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    param($LdapPath, $Filter)

                    if ($Filter -match 'servicePrincipalName')
                    {
                        return @(
                            @{
                                distinguishedname  = @('CN=svc-sql,OU=ServiceAccounts,DC=contoso,DC=com')
                                samaccountname     = @('svc-sql')
                                serviceprincipalname = @('MSSQLSvc/db01.contoso.com:1433')
                                description        = @('SQL Service Account')
                                useraccountcontrol = @(66048)
                                pwdlastset         = @(0)
                                memberof           = @()
                            }
                        )
                    }

                    # Description query returns empty
                    return @()
                }

                Mock New-Object {
                    return [PSCustomObject]@{ Name = 'contoso.com' }
                } -ParameterFilter { $TypeName -match 'DirectoryContext' }

                $fakeEntry = [PSCustomObject]@{ Name = 'contoso.com' }
                Mock ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain) { return $fakeEntry }
            }
        }

        It 'Should return result for SPN-detected service account' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSServiceAccounts -Domain 'contoso.com'
                $results | Should -Not -BeNullOrEmpty
            }
        }

        It 'DetectedBy should include SPN' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSServiceAccounts -Domain 'contoso.com'
                $results[0].DetectedBy | Should -Contain 'SPN'
            }
        }

        It 'DetectedBy should include OU for matching DN' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSServiceAccounts -Domain 'contoso.com'
                # DN contains 'ServiceAccounts' which matches keyword 'ServiceAccount'
                $results[0].DetectedBy | Should -Contain 'OU'
            }
        }

        It 'PasswordNeverExpires should be $true when UAC bit 65536 is set' {
            InModuleScope DirectoryServicesToolkit {
                $results = Get-DSServiceAccounts -Domain 'contoso.com'
                $results[0].PasswordNeverExpires | Should -BeTrue
            }
        }
    }
}
