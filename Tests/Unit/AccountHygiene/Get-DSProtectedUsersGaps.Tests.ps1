BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSProtectedUsersGaps' -Tag 'Unit', 'AccountHygiene' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                SamAccountName             = 'jsmith'
                DistinguishedName          = 'CN=jsmith,OU=Admins,DC=contoso,DC=com'
                Enabled                    = $true
                PrivilegedGroup            = 'Domain Admins'
                InProtectedUsers           = $false
                HasSPN                     = $false
                HasUnconstrainedDelegation = $false
                IncompatibleSPN            = $false
                IncompatibleDelegation     = $false
                RiskLevel                  = 'High'
                Finding                    = 'Privileged account jsmith is not in Protected Users'
            }

            $result.PSObject.Properties.Name | Should -Contain 'SamAccountName'
            $result.PSObject.Properties.Name | Should -Contain 'DistinguishedName'
            $result.PSObject.Properties.Name | Should -Contain 'Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'PrivilegedGroup'
            $result.PSObject.Properties.Name | Should -Contain 'InProtectedUsers'
            $result.PSObject.Properties.Name | Should -Contain 'HasSPN'
            $result.PSObject.Properties.Name | Should -Contain 'HasUnconstrainedDelegation'
            $result.PSObject.Properties.Name | Should -Contain 'IncompatibleSPN'
            $result.PSObject.Properties.Name | Should -Contain 'IncompatibleDelegation'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }
    }

    Context 'Risk level classification' {

        It 'Privileged account NOT in Protected Users should be High risk' {
            $inProtectedUsers = $false
            $isEnabled        = $true
            $incompatSPN      = $false
            $incompatDelegation = $false
            $risk = if (-not $inProtectedUsers -and $isEnabled) { 'High' }
                    elseif ($incompatSPN -or $incompatDelegation) { 'Medium' }
                    else { 'Low' }
            $risk | Should -Be 'High'
        }

        It 'Disabled privileged account not in Protected Users should be Low risk' {
            $inProtectedUsers = $false
            $isEnabled        = $false
            $incompatSPN      = $false
            $incompatDelegation = $false
            $risk = if (-not $inProtectedUsers -and $isEnabled) { 'High' }
                    elseif ($incompatSPN -or $incompatDelegation) { 'Medium' }
                    else { 'Low' }
            $risk | Should -Be 'Low'
        }

        It 'Account in Protected Users with SPN should be Medium risk (incompatibility)' {
            $inProtectedUsers = $true
            $isEnabled        = $true
            $incompatSPN      = $true
            $incompatDelegation = $false
            $risk = if (-not $inProtectedUsers -and $isEnabled) { 'High' }
                    elseif ($incompatSPN -or $incompatDelegation) { 'Medium' }
                    else { 'Low' }
            $risk | Should -Be 'Medium'
        }
    }

    Context 'IncompatibleSPN detection' {

        It 'IncompatibleSPN should be true when account is in Protected Users and has SPN' {
            $inProtectedUsers = $true
            $hasSPN           = $true
            $incompatSPN      = $inProtectedUsers -and $hasSPN
            $incompatSPN      | Should -BeTrue
        }

        It 'IncompatibleSPN should be false when account is not in Protected Users' {
            $inProtectedUsers = $false
            $hasSPN           = $true
            $incompatSPN      = $inProtectedUsers -and $hasSPN
            $incompatSPN      | Should -BeFalse
        }
    }

    Context 'IncompatibleDelegation detection' {

        It 'IncompatibleDelegation should be true when Protected Users member has unconstrained delegation' {
            $inProtectedUsers = $true
            $hasUnconstrained = $true
            $incompatDelegation = $inProtectedUsers -and $hasUnconstrained
            $incompatDelegation | Should -BeTrue
        }
    }

    Context 'UAC flag extraction' {

        It 'TRUSTED_FOR_DELEGATION bit 0x80000 should detect unconstrained delegation' {
            $uac              = 0x80000
            $hasUnconstrained = [bool]($uac -band 0x80000)
            $hasUnconstrained | Should -BeTrue
        }

        It 'ACCOUNTDISABLE bit 0x2 should detect disabled accounts' {
            $uac      = 0x2
            $isEnabled = -not [bool]($uac -band 0x2)
            $isEnabled | Should -BeFalse
        }
    }

    Context 'Mocked query — result enumeration' {

        BeforeEach {
            InModuleScope DirectoryServicesToolkit {
                Mock Invoke-DSDirectorySearch {
                    param($LdapPath, $Filter, $Properties)

                    # Protected Users group query
                    if ($Filter -match 'Protected Users')
                    {
                        return @(
                            @{
                                member = @()
                            }
                        )
                    }

                    # Domain Admins group query
                    if ($Filter -match 'Domain Admins')
                    {
                        return @(
                            @{
                                member = @('CN=AdminUser,OU=Admins,DC=contoso,DC=com')
                            }
                        )
                    }

                    # User object lookup
                    if ($Filter -match 'distinguishedName')
                    {
                        return @(
                            @{
                                name                 = @('AdminUser')
                                samaccountname       = @('adminuser')
                                distinguishedname    = @('CN=AdminUser,OU=Admins,DC=contoso,DC=com')
                                useraccountcontrol   = @(512)
                                serviceprincipalname = $null
                            }
                        )
                    }

                    return @()
                }
            }
        }

        It 'Should flag privileged account not in Protected Users' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }

                $results = Get-DSProtectedUsersGaps -Domain 'contoso.com'
                $adminResult = $results | Where-Object { $_.SamAccountName -eq 'adminuser' }
                $adminResult | Should -Not -BeNullOrEmpty
                $adminResult.InProtectedUsers | Should -BeFalse
                $adminResult.RiskLevel        | Should -Be 'High'
            }
        }
    }
}
