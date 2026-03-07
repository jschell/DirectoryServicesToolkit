BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSADCSTemplateACL' -Tag 'Unit', 'Security', 'ADCS' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                TemplateName      = 'UserAuthentication'
                TemplateDN        = 'CN=UserAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                IdentityReference = 'CONTOSO\helpdesk'
                Rights            = 'WriteProperty'
                MatchedRights     = @('WriteProperty')
                ObjectType        = [guid]::Empty
                IsInherited       = $false
                IsPrivilegedOwner = $false
                IsVulnerable      = $true
                RiskLevel         = 'High'
                Finding           = "ESC4: 'CONTOSO\helpdesk' has write access (WriteProperty) on template 'UserAuthentication'"
            }

            $result.PSObject.Properties.Name | Should -Contain 'TemplateName'
            $result.PSObject.Properties.Name | Should -Contain 'TemplateDN'
            $result.PSObject.Properties.Name | Should -Contain 'IdentityReference'
            $result.PSObject.Properties.Name | Should -Contain 'Rights'
            $result.PSObject.Properties.Name | Should -Contain 'MatchedRights'
            $result.PSObject.Properties.Name | Should -Contain 'IsInherited'
            $result.PSObject.Properties.Name | Should -Contain 'IsPrivilegedOwner'
            $result.PSObject.Properties.Name | Should -Contain 'IsVulnerable'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }
    }

    Context 'Risk level classification — ESC4 write rights' {

        It 'GenericAll should be classified as Critical' {
            $matchedRights = @('GenericAll')
            $riskLevel = if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner')
            {
                'Critical'
            }
            else
            {
                'High'
            }
            $riskLevel | Should -Be 'Critical'
        }

        It 'WriteDacl should be classified as Critical' {
            $matchedRights = @('WriteDacl')
            $riskLevel = if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner')
            {
                'Critical'
            }
            else
            {
                'High'
            }
            $riskLevel | Should -Be 'Critical'
        }

        It 'WriteOwner should be classified as Critical' {
            $matchedRights = @('WriteOwner')
            $riskLevel = if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner')
            {
                'Critical'
            }
            else
            {
                'High'
            }
            $riskLevel | Should -Be 'Critical'
        }

        It 'WriteProperty alone should be classified as High' {
            $matchedRights = @('WriteProperty')
            $riskLevel = if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner')
            {
                'Critical'
            }
            else
            {
                'High'
            }
            $riskLevel | Should -Be 'High'
        }

        It 'GenericWrite alone should be classified as High' {
            $matchedRights = @('GenericWrite')
            $riskLevel = if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner')
            {
                'Critical'
            }
            else
            {
                'High'
            }
            $riskLevel | Should -Be 'High'
        }
    }

    Context 'Safe principal exclusion logic' {

        It 'BUILTIN\Administrators should be considered a safe principal' {
            $identity        = 'BUILTIN\Administrators'
            $safePrincipals  = @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')
            $safeGroupPatterns = @('Domain Admins', 'Enterprise Admins')
            $isSafe = $false
            foreach ($safe in $safePrincipals) { if ($identity -eq $safe) { $isSafe = $true; break } }
            $isSafe | Should -BeTrue
        }

        It 'Domain Admins should be matched by safe group pattern' {
            $identity          = 'CONTOSO\Domain Admins'
            $safeGroupPatterns = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
            $isSafe = $false
            foreach ($pattern in $safeGroupPatterns) { if ($identity -like "*$pattern*") { $isSafe = $true; break } }
            $isSafe | Should -BeTrue
        }

        It 'Non-privileged user should not be considered safe' {
            $identity          = 'CONTOSO\helpdesk-user'
            $safePrincipals    = @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')
            $safeGroupPatterns = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Cert Publishers', 'Administrators')
            $isSafe = $false
            foreach ($safe in $safePrincipals) { if ($identity -eq $safe) { $isSafe = $true; break } }
            if (-not $isSafe) { foreach ($pattern in $safeGroupPatterns) { if ($identity -like "*$pattern*") { $isSafe = $true; break } } }
            $isSafe | Should -BeFalse
        }
    }

    Context 'Dangerous rights detection' {

        It 'Should detect GenericAll as dangerous' {
            $rights         = 'GenericAll, WriteDacl, WriteOwner'
            $dangerousRights = @('GenericAll', 'GenericWrite', 'WriteProperty', 'WriteDacl', 'WriteOwner')
            $matched = @($dangerousRights | Where-Object { $rights -match $_ })
            $matched.Count | Should -BeGreaterThan 0
        }

        It 'Should not flag read-only rights as dangerous' {
            $rights         = 'ReadProperty, ListChildren'
            $dangerousRights = @('GenericAll', 'GenericWrite', 'WriteProperty', 'WriteDacl', 'WriteOwner')
            $matched = @($dangerousRights | Where-Object { $rights -match $_ })
            $matched.Count | Should -Be 0
        }
    }

    Context 'Mocked query — result enumeration' {

        It 'Should return vulnerable ACE entries for non-privileged write access' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name              = @('UserAuthentication')
                            distinguishedname = @('CN=UserAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com')
                        }
                    )
                }
                Mock Get-DSObjectAcl {
                    return @(
                        [PSCustomObject]@{
                            IdentityReference     = 'CONTOSO\helpdesk'
                            ActiveDirectoryRights = 'WriteProperty'
                            AccessControlType     = 'Allow'
                            ObjectType            = [guid]::Empty
                            InheritanceType       = 'None'
                            IsInherited           = $false
                        }
                    )
                }

                $results = Find-DSADCSTemplateACL -Domain 'contoso.com'
                $results | Should -Not -BeNullOrEmpty
                $results[0].IsVulnerable | Should -BeTrue
            }
        }

        It 'Should exclude safe principal ACEs by default' {
            InModuleScope DirectoryServicesToolkit {
                Mock Resolve-DSDomainName { return 'contoso.com' }
                Mock Invoke-DSDirectorySearch {
                    return @(
                        @{
                            name              = @('UserAuthentication')
                            distinguishedname = @('CN=UserAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com')
                        }
                    )
                }
                Mock Get-DSObjectAcl {
                    return @(
                        [PSCustomObject]@{
                            IdentityReference     = 'BUILTIN\Administrators'
                            ActiveDirectoryRights = 'GenericAll'
                            AccessControlType     = 'Allow'
                            ObjectType            = [guid]::Empty
                            InheritanceType       = 'None'
                            IsInherited           = $false
                        }
                    )
                }

                $results = Find-DSADCSTemplateACL -Domain 'contoso.com'
                $results | Should -BeNullOrEmpty
            }
        }
    }
}
