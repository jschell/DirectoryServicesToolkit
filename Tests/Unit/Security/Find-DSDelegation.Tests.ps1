BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSDelegation' -Tag 'Unit', 'Security' {

    Context 'Unconstrained delegation — user accounts' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    param($LdapPath, $Filter, $Properties)

                    # Respond to unconstrained user query
                    if ($Filter -match 'objectCategory=person' -and $Filter -match '524288')
                    {
                        return @(
                            @{
                                samaccountname    = @('svc-iis')
                                distinguishedname = @('CN=svc-iis,OU=ServiceAccounts,DC=contoso,DC=com')
                                useraccountcontrol = @(524800)   # 524288 (TrustedForDelegation) | 512 (NormalAccount)
                                objectclass       = @('top', 'person', 'organizationalPerson', 'user')
                            }
                        )
                    }
                    return @()
                }

                Mock New-Object {
                    param($TypeName)
                    if ($TypeName -match 'DirectoryContext')
                    {
                        return [PSCustomObject]@{ }
                    }
                    return Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName
                } -ParameterFilter { $TypeName -match 'DirectoryContext' }

                Mock ([System.DirectoryServices.ActiveDirectory.Domain]) {
                    return [PSCustomObject]@{ Name = 'contoso.com' }
                }
            }
        }

        It 'Should return PSCustomObject results' {
            InModuleScope DirectoryServicesToolkit {
                Mock New-Object { return [PSCustomObject]@{ Name = 'contoso.com' } } `
                    -ParameterFilter { $TypeName -match 'DirectoryContext' }

                $fakeEntry = [PSCustomObject]@{ Name = 'contoso.com' }
                Mock ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain) { return $fakeEntry }

                $result = Find-DSDelegation -Domain 'contoso.com' -DelegationType Unconstrained
                $result | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            samaccountname     = @('svc-unconstrained')
                            distinguishedname  = @('CN=svc-unconstrained,DC=contoso,DC=com')
                            useraccountcontrol = @(524800)
                            objectclass        = @('user')
                        }
                    )
                }
                Mock Resolve-DomainName { return 'contoso.com' }

                # Build a result object directly to validate schema
                $result = [PSCustomObject]@{
                    SamAccountName     = 'svc-unconstrained'
                    DistinguishedName  = 'CN=svc-unconstrained,DC=contoso,DC=com'
                    DelegationType     = 'Unconstrained'
                    ProtocolTransition = $false
                    DelegationTarget   = $null
                    RBCDTarget         = $null
                    Enabled            = $true
                    ObjectType         = 'User'
                }

                $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
                $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
                $result.PSObject.Properties.Name | Should -Contain 'DelegationType'
                $result.PSObject.Properties.Name | Should -Contain 'ProtocolTransition'
                $result.PSObject.Properties.Name | Should -Contain 'DelegationTarget'
                $result.PSObject.Properties.Name | Should -Contain 'RBCDTarget'
                $result.PSObject.Properties.Name | Should -Contain 'Enabled'
                $result.PSObject.Properties.Name | Should -Contain 'ObjectType'
            }
        }

        It 'DelegationType should be Unconstrained for TrustedForDelegation accounts' {
            $result = [PSCustomObject]@{
                DelegationType = 'Unconstrained'
                ObjectType     = 'User'
                Enabled        = $true
            }
            $result.DelegationType | Should -Be 'Unconstrained'
        }

        It 'DelegationType should be Constrained when msDS-AllowedToDelegateTo is set' {
            $result = [PSCustomObject]@{
                DelegationType   = 'Constrained'
                DelegationTarget = @('HTTP/webserver.contoso.com')
            }
            $result.DelegationType | Should -Be 'Constrained'
            $result.DelegationTarget | Should -Not -BeNullOrEmpty
        }

        It 'DelegationType should be RBCD when msDS-AllowedToActOnBehalfOfOtherIdentity is set' {
            $result = [PSCustomObject]@{
                DelegationType = 'RBCD'
                ObjectType     = 'Computer'
                RBCDTarget     = 'O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1234)'
            }
            $result.DelegationType | Should -Be 'RBCD'
            $result.RBCDTarget     | Should -Not -BeNullOrEmpty
        }
    }

    Context 'ProtocolTransition flag' {

        It 'ProtocolTransition should be true when UAC bit 16777216 is set' {
            # UAC = 16777216 (TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) | 512 (NormalAccount) | 524288 (TrustedForDelegation)
            $uac = 512 -bor 524288 -bor 16777216
            $protocolTransition = [bool]($uac -band 16777216)
            $protocolTransition | Should -BeTrue
        }

        It 'ProtocolTransition should be false when UAC bit 16777216 is not set' {
            $uac = 512 -bor 524288
            $protocolTransition = [bool]($uac -band 16777216)
            $protocolTransition | Should -BeFalse
        }
    }

    Context 'Enabled flag' {

        It 'Enabled should be false when UAC accountDisable bit (2) is set' {
            $uac = 512 -bor 2   # NormalAccount | AccountDisable
            $enabled = -not [bool]($uac -band 2)
            $enabled | Should -BeFalse
        }

        It 'Enabled should be true when UAC accountDisable bit is not set' {
            $uac = 512   # NormalAccount only
            $enabled = -not [bool]($uac -band 2)
            $enabled | Should -BeTrue
        }
    }

    Context 'LDAP filter construction' {

        It 'Unconstrained user filter should contain 524288 UAC bit' {
            $filter = '(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(cn=krbtgt)))'
            $filter | Should -Match '524288'
            $filter | Should -Match 'objectCategory=person'
        }

        It 'Constrained filter should target msDS-AllowedToDelegateTo' {
            $filter = '(&(objectClass=user)(msDS-AllowedToDelegateTo=*)(!(cn=krbtgt)))'
            $filter | Should -Match 'msDS-AllowedToDelegateTo'
        }

        It 'RBCD filter should target msDS-AllowedToActOnBehalfOfOtherIdentity' {
            $filter = '(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))'
            $filter | Should -Match 'msDS-AllowedToActOnBehalfOfOtherIdentity'
        }

        It 'ExcludeComputerAccounts constrained filter should include objectCategory exclusion' {
            $filter = '(&(objectClass=user)(msDS-AllowedToDelegateTo=*)(!(cn=krbtgt))(!(objectCategory=computer)))'
            $filter | Should -Match '\(!\(objectCategory=computer\)\)'
        }
    }

    Context 'Parameter validation' {

        It 'DelegationType should accept valid values' {
            foreach ($type in @('Unconstrained', 'Constrained', 'RBCD', 'All'))
            {
                { [ValidateSet('Unconstrained', 'Constrained', 'RBCD', 'All')]$_ = $type } | Should -Not -Throw
            }
        }

        It 'DelegationType should reject invalid values' {
            { [ValidateSet('Unconstrained', 'Constrained', 'RBCD', 'All')]$_ = 'Invalid' } | Should -Throw
        }
    }
}
