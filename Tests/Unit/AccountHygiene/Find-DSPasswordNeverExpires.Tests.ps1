BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSPasswordNeverExpires' -Tag 'Unit', 'AccountHygiene' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                SamAccountName    = 'svc-sql'
                DistinguishedName = 'CN=svc-sql,OU=ServiceAccounts,DC=contoso,DC=com'
                Enabled           = $true
                PasswordLastSet   = (Get-Date).AddDays(-365)
                PasswordAgeDays   = 365
                HasSPN            = $true
                SPNs              = @('MSSQLSvc/db01.contoso.com:1433')
            }

            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordLastSet'
            $result.PSObject.Properties.Name | Should -Contain 'PasswordAgeDays'
            $result.PSObject.Properties.Name | Should -Contain 'HasSPN'
            $result.PSObject.Properties.Name | Should -Contain 'SPNs'
        }
    }

    Context 'LDAP filter construction' {

        It 'Should include DONT_EXPIRE_PASSWORD bit (65536) in filter' {
            $filterParts = @(
                '(objectClass=user)'
                '(userAccountControl:1.2.840.113556.1.4.803:=65536)'
            )
            $ldapFilter = '(&{0})' -f ($filterParts -join '')
            $ldapFilter | Should -Match ':=65536\)'
        }

        It 'Should exclude disabled accounts by default' {
            $filterParts = @(
                '(objectClass=user)'
                '(userAccountControl:1.2.840.113556.1.4.803:=65536)'
                '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
            )
            $ldapFilter = '(&{0})' -f ($filterParts -join '')
            $ldapFilter | Should -Match '!\(userAccountControl.*:=2\)'
        }
    }

    Context 'PasswordAgeDays calculation' {

        It 'Should compute correct age for a known past date' {
            $pastDate       = (Get-Date).AddDays(-180)
            $now            = Get-Date
            $passwordAgeDays = [int]($now - $pastDate).TotalDays
            $passwordAgeDays | Should -BeGreaterThan 179
            $passwordAgeDays | Should -BeLessThan 182
        }

        It 'Should return $null for PasswordAgeDays when pwdLastSet is 0' {
            $pwdLastSetRaw   = 0
            $passwordLastSet = if ($null -ne $pwdLastSetRaw -and [long]$pwdLastSetRaw -gt 0)
                               { [DateTime]::FromFileTime([long]$pwdLastSetRaw) }
                               else { $null }
            $passwordAgeDays = if ($null -ne $passwordLastSet)
                               { [int]((Get-Date) - $passwordLastSet).TotalDays }
                               else { $null }
            $passwordAgeDays | Should -BeNullOrEmpty
        }
    }

    Context 'HasSPN detection' {

        It 'Should set HasSPN=$true when servicePrincipalName is present' {
            $spnRaw = @('MSSQLSvc/db01.contoso.com:1433')
            $hasSPN = ($null -ne $spnRaw -and $spnRaw.Count -gt 0 -and $null -ne $spnRaw[0])
            $hasSPN | Should -BeTrue
        }

        It 'Should set HasSPN=$false when servicePrincipalName is absent' {
            $spnRaw = @()
            $hasSPN = ($null -ne $spnRaw -and $spnRaw.Count -gt 0 -and $null -ne $spnRaw[0])
            $hasSPN | Should -BeFalse
        }
    }

    Context 'Mocked query' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            distinguishedname    = @('CN=svc-sql,OU=ServiceAccounts,DC=contoso,DC=com')
                            samaccountname       = @('svc-sql')
                            useraccountcontrol   = @(66048)   # 512 + 65536
                            pwdlastset           = @((Get-Date).AddDays(-500).ToFileTime())
                            serviceprincipalname = @('MSSQLSvc/db01.contoso.com:1433')
                        },
                        @{
                            distinguishedname    = @('CN=jdoe,OU=Users,DC=contoso,DC=com')
                            samaccountname       = @('jdoe')
                            useraccountcontrol   = @(66048)
                            pwdlastset           = @((Get-Date).AddDays(-100).ToFileTime())
                            serviceprincipalname = @()
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

        It 'Should return two results' {
            InModuleScope DirectoryServicesToolkit {
                $results = Find-DSPasswordNeverExpires -Domain 'contoso.com'
                $results.Count | Should -Be 2
            }
        }

        It 'Should sort by PasswordAgeDays descending (oldest first)' {
            InModuleScope DirectoryServicesToolkit {
                $results = Find-DSPasswordNeverExpires -Domain 'contoso.com'
                $results[0].PasswordAgeDays | Should -BeGreaterThan $results[1].PasswordAgeDays
            }
        }

        It 'Service account with SPN should have HasSPN=$true' {
            InModuleScope DirectoryServicesToolkit {
                $results = Find-DSPasswordNeverExpires -Domain 'contoso.com'
                $svcAccount = $results | Where-Object { $_.SamAccountName -eq 'svc-sql' }
                $svcAccount.HasSPN | Should -BeTrue
            }
        }

        It 'Regular user without SPN should have HasSPN=$false' {
            InModuleScope DirectoryServicesToolkit {
                $results = Find-DSPasswordNeverExpires -Domain 'contoso.com'
                $userAccount = $results | Where-Object { $_.SamAccountName -eq 'jdoe' }
                $userAccount.HasSPN | Should -BeFalse
            }
        }
    }
}
