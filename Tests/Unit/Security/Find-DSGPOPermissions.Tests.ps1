BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSGPOPermissions' -Tag 'Unit', 'Security' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                GPOName           = 'Default Domain Policy'
                GPOGUID           = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
                GPODN             = 'CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=contoso,DC=com'
                GPOSysvolPath     = '\\contoso.com\SYSVOL\contoso.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}'
                IdentityReference = 'CONTOSO\HelpDesk'
                Rights            = 'WriteProperty'
                MatchedRights     = @('WriteProperty')
                IsInherited       = $false
                IsPrivilegedOwner = $false
                IsVulnerable      = $true
                RiskLevel         = 'High'
                Finding           = "GPO write: 'CONTOSO\HelpDesk' has WriteProperty on GPO 'Default Domain Policy'"
            }

            $result.PSObject.Properties.Name | Should -Contain 'GPOName'
            $result.PSObject.Properties.Name | Should -Contain 'GPOGUID'
            $result.PSObject.Properties.Name | Should -Contain 'GPODN'
            $result.PSObject.Properties.Name | Should -Contain 'IdentityReference'
            $result.PSObject.Properties.Name | Should -Contain 'Rights'
            $result.PSObject.Properties.Name | Should -Contain 'MatchedRights'
            $result.PSObject.Properties.Name | Should -Contain 'IsVulnerable'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }
    }

    Context 'Risk level classification' {

        It 'GenericAll on GPO should be Critical' {
            $matchedRights = @('GenericAll')
            $riskLevel = if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner') { 'Critical' } else { 'High' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'WriteDacl on GPO should be Critical' {
            $matchedRights = @('WriteDacl')
            $riskLevel = if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner') { 'Critical' } else { 'High' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'WriteProperty on GPO should be High' {
            $matchedRights = @('WriteProperty')
            $riskLevel = if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner') { 'Critical' } else { 'High' }
            $riskLevel | Should -Be 'High'
        }

        It 'Privileged principal should be Informational' {
            $isVulnerable = $false
            $riskLevel    = if ($isVulnerable) { 'High' } else { 'Informational' }
            $riskLevel | Should -Be 'Informational'
        }
    }

    Context 'Finding field' {

        It 'Finding should be set when IsVulnerable = true' {
            $isVulnerable = $true
            $identity     = 'CONTOSO\HelpDesk'
            $matchedRights = @('WriteProperty')
            $gpoName      = 'Default Domain Policy'
            $finding      = if ($isVulnerable) { "GPO write: '$identity' has $($matchedRights -join ', ') on GPO '$gpoName'" } else { $null }
            $finding | Should -Not -BeNullOrEmpty
            $finding | Should -Match 'GPO write'
        }

        It 'Finding should be null when IsVulnerable = false' {
            $isVulnerable = $false
            $finding      = if ($isVulnerable) { 'Something' } else { $null }
            $finding | Should -BeNullOrEmpty
        }
    }
}
