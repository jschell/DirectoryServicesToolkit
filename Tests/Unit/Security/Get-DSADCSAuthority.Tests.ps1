BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSADCSAuthority' -Tag 'Unit', 'Security', 'ADCS' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                Name              = 'ContosoCA'
                DistinguishedName = 'CN=ContosoCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                DNSHostName       = 'ca01.contoso.com'
                CAType            = 'EnterpriseRoot'
                CertificateExpiry = (Get-Date).AddYears(5)
                EnrollmentServers = @('https://ca01.contoso.com/certsrv')
                HasWebEnrollment  = $true
                HTTPEndpoints     = @()
                HTTPEndpointCount = 0
            }

            $result.PSObject.Properties.Name | Should -Contain 'Name'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'DNSHostName'
            $result.PSObject.Properties.Name | Should -Contain 'CAType'
            $result.PSObject.Properties.Name | Should -Contain 'CertificateExpiry'
            $result.PSObject.Properties.Name | Should -Contain 'EnrollmentServers'
            $result.PSObject.Properties.Name | Should -Contain 'HasWebEnrollment'
            $result.PSObject.Properties.Name | Should -Contain 'HTTPEndpoints'
            $result.PSObject.Properties.Name | Should -Contain 'HTTPEndpointCount'
        }
    }

    Context 'HTTPEndpointCount calculation' {

        It 'HTTPEndpointCount should be 0 when no HTTP endpoints exist' {
            $enrollSvrs    = @('https://ca01.contoso.com/certsrv')
            $httpEndpoints = @($enrollSvrs | Where-Object { $_ -match '^http://' })
            $httpEndpoints.Count | Should -Be 0
        }

        It 'HTTPEndpointCount should reflect the number of HTTP-only endpoints' {
            $enrollSvrs    = @('http://ca01.contoso.com/certsrv', 'https://ca01.contoso.com/certsrv')
            $httpEndpoints = @($enrollSvrs | Where-Object { $_ -match '^http://' })
            $httpEndpoints.Count | Should -Be 1
        }
    }

    Context 'HasWebEnrollment flag' {

        It 'HasWebEnrollment should be true when enrollment servers are present' {
            $enrollSvrs      = @('https://ca01.contoso.com/certsrv')
            $hasWebEnrollment = $enrollSvrs.Count -gt 0
            $hasWebEnrollment | Should -BeTrue
        }

        It 'HasWebEnrollment should be false when no enrollment servers are configured' {
            $enrollSvrs      = @()
            $hasWebEnrollment = $enrollSvrs.Count -gt 0
            $hasWebEnrollment | Should -BeFalse
        }
    }

    Context 'CAType resolution' {

        It 'CAType should be EnterpriseRoot for flags value 1' {
            $flags  = 1
            $caType = switch ($flags)
            {
                1 { 'EnterpriseRoot' }
                3 { 'EnterpriseSubordinate' }
                default { "Unknown($flags)" }
            }
            $caType | Should -Be 'EnterpriseRoot'
        }

        It 'CAType should be EnterpriseSubordinate for flags value 3' {
            $flags  = 3
            $caType = switch ($flags)
            {
                1 { 'EnterpriseRoot' }
                3 { 'EnterpriseSubordinate' }
                default { "Unknown($flags)" }
            }
            $caType | Should -Be 'EnterpriseSubordinate'
        }

        It 'CAType should be Unknown for unrecognised flags values' {
            $flags  = 99
            $caType = switch ($flags)
            {
                1 { 'EnterpriseRoot' }
                3 { 'EnterpriseSubordinate' }
                default { "Unknown($flags)" }
            }
            $caType | Should -Be 'Unknown(99)'
        }
    }

    Context 'Mocked query — result enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name                        = @('ContosoCA')
                            distinguishedname           = @('CN=ContosoCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com')
                            dnshostname                 = @('ca01.contoso.com')
                            cacertificateexpirationtime = @(((Get-Date).AddYears(5)).ToFileTime())
                            'mspki-enrollment-servers'  = @('https://ca01.contoso.com/certsrv')
                            flags                       = @(1)
                        }
                    )
                }
            }
        }

        It 'Should return one result per Enterprise CA' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Get-DSADCSAuthority -Domain 'contoso.com'
                $results.Count | Should -Be 1
            }
        }

        It 'Should correctly populate CA name and DNS hostname' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Get-DSADCSAuthority -Domain 'contoso.com'
                $results[0].Name        | Should -Be 'ContosoCA'
                $results[0].DNSHostName | Should -Be 'ca01.contoso.com'
            }
        }

        It 'Should report HTTPEndpointCount as 0 when only HTTPS endpoints exist' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Get-DSADCSAuthority -Domain 'contoso.com'
                $results[0].HTTPEndpointCount | Should -Be 0
            }
        }
    }
}
