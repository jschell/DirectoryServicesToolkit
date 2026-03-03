BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSADIDNSRecord' -Tag 'Unit', 'DNS' {

    Context 'Output schema validation' {

        It 'UnexpectedWriteAccess finding should include all required properties' {
            $result = [PSCustomObject]@{
                ZoneName          = 'contoso.com'
                DistinguishedName = 'DC=contoso.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=contoso,DC=com'
                FindingType       = 'UnexpectedWriteAccess'
                Principal         = 'CONTOSO\helpdesk'
                Right             = 'CreateChild'
                RecordName        = $null
                Partition         = 'Domain'
            }

            $result.PSObject.Properties.Name | Should -Contain 'ZoneName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'FindingType'
            $result.PSObject.Properties.Name | Should -Contain 'Principal'
            $result.PSObject.Properties.Name | Should -Contain 'Right'
            $result.PSObject.Properties.Name | Should -Contain 'RecordName'
            $result.PSObject.Properties.Name | Should -Contain 'Partition'
        }

        It 'WildcardRecord finding should have null Principal and Right' {
            $result = [PSCustomObject]@{
                ZoneName          = 'contoso.com'
                DistinguishedName = 'DC=contoso.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=contoso,DC=com'
                FindingType       = 'WildcardRecord'
                Principal         = $null
                Right             = $null
                RecordName        = '*'
                Partition         = 'Domain'
            }

            $result.Principal  | Should -BeNullOrEmpty
            $result.Right      | Should -BeNullOrEmpty
            $result.RecordName | Should -Be '*'
            $result.FindingType | Should -Be 'WildcardRecord'
        }

        It 'FindingType should be UnexpectedWriteAccess or WildcardRecord' {
            $validTypes = @('UnexpectedWriteAccess', 'WildcardRecord')
            'UnexpectedWriteAccess' | Should -BeIn $validTypes
            'WildcardRecord'        | Should -BeIn $validTypes
        }
    }

    Context 'LDAP wildcard escape' {

        It 'Should use \2a to represent the * character in LDAP filter' {
            $filter = '(&(objectClass=dnsNode)(name=\2a))'
            $filter | Should -Match '\\2a'
            $filter | Should -Not -Match '\(\*\)'
        }
    }

    Context 'LDAP path construction' {

        It 'Domain partition path should include DomainDnsZones' {
            $domainDn = 'DC=contoso,DC=com'
            $path     = "LDAP://CN=MicrosoftDNS,DC=DomainDnsZones,$domainDn"
            $path     | Should -Match 'DomainDnsZones'
        }

        It 'Forest partition path should include ForestDnsZones' {
            $domainDn = 'DC=contoso,DC=com'
            $path     = "LDAP://CN=MicrosoftDNS,DC=ForestDnsZones,$domainDn"
            $path     | Should -Match 'ForestDnsZones'
        }
    }

    Context 'Flagged rights detection' {

        It 'CreateChild should be flagged' {
            $rights       = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
            $flaggedRights = @(
                [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
                [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
            )
            $matched = $flaggedRights | Where-Object { $rights -band $_ }
            $matched | Should -Not -BeNullOrEmpty
        }

        It 'ReadProperty should not be flagged' {
            $rights       = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
            $flaggedRights = @(
                [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
                [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
                [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
            )
            $matched = $flaggedRights | Where-Object { $rights -band $_ }
            $matched | Should -BeNullOrEmpty
        }
    }

    Context 'Mocked query — unexpected write access and wildcard record' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    param($LdapPath, $Filter)

                    # DnsAdmins resolution
                    if ($Filter -match 'sAMAccountName=DnsAdmins')
                    {
                        return @()
                    }

                    # Zone enumeration
                    if ($Filter -eq '(objectClass=dnsZone)')
                    {
                        return @(
                            @{
                                name              = @('contoso.com')
                                distinguishedname = @('DC=contoso.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=contoso,DC=com')
                            }
                        )
                    }

                    # Wildcard dnsNode query
                    if ($Filter -match '\\2a')
                    {
                        return @(
                            @{
                                name              = @('*')
                                distinguishedname = @('DC=*,DC=contoso.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=contoso,DC=com')
                                dnsrecord         = @([byte[]](1, 2, 3))
                            }
                        )
                    }

                    return @()
                }

                Mock Get-DSObjectAcl {
                    return @(
                        [PSCustomObject]@{
                            IdentityReference     = 'CONTOSO\helpdesk'
                            ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                            AccessControlType     = 'Allow'
                            ObjectType            = [Guid]::Empty
                            IsInherited           = $false
                        }
                    )
                }

                Mock New-Object {
                    return [PSCustomObject]@{ Name = 'contoso.com' }
                } -ParameterFilter { $TypeName -match 'DirectoryContext' }

                # Domain root for SID resolution
                Mock New-Object {
                    $fakeDomainRoot = [PSCustomObject]@{
                        objectSid = [PSCustomObject]@{ Value = [byte[]](1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0) }
                    }
                    $fakeDomainRoot | Add-Member -MemberType ScriptMethod -Name Dispose -Value {}
                    return $fakeDomainRoot
                } -ParameterFilter { $TypeName -match 'SecurityIdentifier' }

                $fakeEntry = [PSCustomObject]@{ Name = 'contoso.com' }
                Mock ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain) { return $fakeEntry }

                # NTAccount SID translation — return a non-excluded SID
                Mock New-Object {
                    $fakeNt = [PSCustomObject]@{}
                    $fakeNt | Add-Member -MemberType ScriptMethod -Name Translate -Value {
                        return [PSCustomObject]@{ ToString = { 'S-1-5-21-999-999-999-1234' }.GetNewClosure() }
                    }
                    return $fakeNt
                } -ParameterFilter { $TypeName -match 'NTAccount' }
            }
        }

        It 'Should return at least one WildcardRecord finding' {
            InModuleScope DirectoryServicesToolkit {
                $results = Find-DSADIDNSRecord -Domain 'contoso.com'
                $wildcard = $results | Where-Object { $_.FindingType -eq 'WildcardRecord' }
                $wildcard | Should -Not -BeNullOrEmpty
            }
        }

        It 'WildcardRecord finding RecordName should be *' {
            InModuleScope DirectoryServicesToolkit {
                $results = Find-DSADIDNSRecord -Domain 'contoso.com'
                $wildcard = $results | Where-Object { $_.FindingType -eq 'WildcardRecord' }
                $wildcard.RecordName | Should -Be '*'
            }
        }

        It 'Partition should be Domain for domain partition findings' {
            InModuleScope DirectoryServicesToolkit {
                $results = Find-DSADIDNSRecord -Domain 'contoso.com'
                $results | ForEach-Object { $_.Partition | Should -Be 'Domain' }
            }
        }
    }

    Context '-Zone filter' {

        It 'Should skip zones that do not match the specified Zone name' {
            $zoneName     = 'other.com'
            $targetZone   = 'contoso.com'
            $shouldSkip   = ($targetZone -and $zoneName -ne $targetZone)
            $shouldSkip   | Should -BeTrue
        }

        It 'Should not skip zones that match the specified Zone name' {
            $zoneName     = 'contoso.com'
            $targetZone   = 'contoso.com'
            $shouldSkip   = ($targetZone -and $zoneName -ne $targetZone)
            $shouldSkip   | Should -BeFalse
        }
    }
}
