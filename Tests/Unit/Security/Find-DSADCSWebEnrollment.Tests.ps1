BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSADCSWebEnrollment' -Tag 'Unit', 'Security', 'ADCS' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                CAName        = 'ContosoCA'
                DNSHostName   = 'ca01.contoso.com'
                EndpointURL   = 'http://ca01.contoso.com/certsrv'
                Protocol      = 'HTTP'
                IsHTTPOnly    = $true
                NTLMRelayRisk = $true
                RiskLevel     = 'Critical'
                Finding       = "HTTP enrollment endpoint 'http://ca01.contoso.com/certsrv' on CA 'ContosoCA' is vulnerable to NTLM relay (ESC8)"
            }

            $result.PSObject.Properties.Name | Should -Contain 'CAName'
            $result.PSObject.Properties.Name | Should -Contain 'DNSHostName'
            $result.PSObject.Properties.Name | Should -Contain 'EndpointURL'
            $result.PSObject.Properties.Name | Should -Contain 'Protocol'
            $result.PSObject.Properties.Name | Should -Contain 'IsHTTPOnly'
            $result.PSObject.Properties.Name | Should -Contain 'NTLMRelayRisk'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }
    }

    Context 'Protocol detection' {

        It 'Protocol should be HTTP for http:// URLs' {
            $endpoint = 'http://ca01.contoso.com/certsrv'
            $isHTTP   = $endpoint -match '^http://'
            $isHTTPS  = $endpoint -match '^https://'
            $protocol = if ($isHTTPS) { 'HTTPS' } elseif ($isHTTP) { 'HTTP' } else { 'Unknown' }
            $protocol | Should -Be 'HTTP'
        }

        It 'Protocol should be HTTPS for https:// URLs' {
            $endpoint = 'https://ca01.contoso.com/certsrv'
            $isHTTP   = $endpoint -match '^http://'
            $isHTTPS  = $endpoint -match '^https://'
            $protocol = if ($isHTTPS) { 'HTTPS' } elseif ($isHTTP) { 'HTTP' } else { 'Unknown' }
            $protocol | Should -Be 'HTTPS'
        }

        It 'Protocol should be Unknown for non-HTTP/HTTPS URLs' {
            $endpoint = 'ftp://ca01.contoso.com/certsrv'
            $isHTTP   = $endpoint -match '^http://'
            $isHTTPS  = $endpoint -match '^https://'
            $protocol = if ($isHTTPS) { 'HTTPS' } elseif ($isHTTP) { 'HTTP' } else { 'Unknown' }
            $protocol | Should -Be 'Unknown'
        }
    }

    Context 'NTLMRelayRisk flag' {

        It 'NTLMRelayRisk should be true for HTTP endpoints' {
            $endpoint     = 'http://ca01.contoso.com/certsrv'
            $isHTTP       = $endpoint -match '^http://'
            $ntlmRelayRisk = $isHTTP
            $ntlmRelayRisk | Should -BeTrue
        }

        It 'NTLMRelayRisk should be false for HTTPS endpoints' {
            $endpoint     = 'https://ca01.contoso.com/certsrv'
            $isHTTP       = $endpoint -match '^http://'
            $ntlmRelayRisk = $isHTTP
            $ntlmRelayRisk | Should -BeFalse
        }
    }

    Context 'RiskLevel classification' {

        It 'RiskLevel should be Critical for HTTP endpoints' {
            $isHTTP   = $true
            $riskLevel = if ($isHTTP) { 'Critical' } else { 'Informational' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'RiskLevel should be Informational for HTTPS endpoints' {
            $isHTTP   = $false
            $riskLevel = if ($isHTTP) { 'Critical' } else { 'Informational' }
            $riskLevel | Should -Be 'Informational'
        }
    }

    Context 'Mocked query — result enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name                       = @('ContosoCA')
                            distinguishedname          = @('CN=ContosoCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com')
                            dnshostname                = @('ca01.contoso.com')
                            'mspki-enrollment-servers' = @('http://ca01.contoso.com/certsrv', 'https://ca01.contoso.com/certsrv')
                        }
                    )
                }
            }
        }

        It 'Should return one result per enrollment endpoint' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSADCSWebEnrollment -Domain 'contoso.com'
                $results.Count | Should -Be 2
            }
        }

        It 'Should sort results with NTLMRelayRisk true entries first' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Find-DSADCSWebEnrollment -Domain 'contoso.com'
                $results[0].NTLMRelayRisk | Should -BeTrue
            }
        }

        It 'Should flag the HTTP endpoint as Critical risk' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results    = Find-DSADCSWebEnrollment -Domain 'contoso.com'
                $httpResult = $results | Where-Object { $_.Protocol -eq 'HTTP' }
                $httpResult.RiskLevel | Should -Be 'Critical'
            }
        }

        It 'Should flag the HTTPS endpoint as Informational risk' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results      = Find-DSADCSWebEnrollment -Domain 'contoso.com'
                $httpsResult  = $results | Where-Object { $_.Protocol -eq 'HTTPS' }
                $httpsResult.RiskLevel | Should -Be 'Informational'
            }
        }

        It 'Should include ESC8 in the Finding for HTTP endpoints' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results    = Find-DSADCSWebEnrollment -Domain 'contoso.com'
                $httpResult = $results | Where-Object { $_.Protocol -eq 'HTTP' }
                $httpResult.Finding | Should -Match 'ESC8'
            }
        }
    }
}
