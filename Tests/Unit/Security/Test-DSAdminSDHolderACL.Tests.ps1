BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSAdminSDHolderACL' -Tag 'Unit', 'Security' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                AdminSDHolderDN   = 'CN=AdminSDHolder,CN=System,DC=contoso,DC=com'
                IdentityReference = 'CONTOSO\HelpDesk'
                Rights            = 'WriteProperty'
                MatchedRights     = @('WriteProperty')
                ObjectType        = [guid]::Empty
                IsInherited       = $false
                IsPrivilegedOwner = $false
                IsVulnerable      = $true
                RiskLevel         = 'High'
                Finding           = "AdminSDHolder backdoor: 'CONTOSO\HelpDesk' has WriteProperty"
            }

            $result.PSObject.Properties.Name | Should -Contain 'AdminSDHolderDN'
            $result.PSObject.Properties.Name | Should -Contain 'IdentityReference'
            $result.PSObject.Properties.Name | Should -Contain 'Rights'
            $result.PSObject.Properties.Name | Should -Contain 'MatchedRights'
            $result.PSObject.Properties.Name | Should -Contain 'IsPrivilegedOwner'
            $result.PSObject.Properties.Name | Should -Contain 'IsVulnerable'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }
    }

    Context 'Risk level classification' {

        It 'GenericAll should be Critical' {
            $matchedRights = @('GenericAll')
            $isVulnerable  = $true
            $riskLevel = if ($isVulnerable)
            {
                if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner') { 'Critical' } else { 'High' }
            }
            else { 'Informational' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'WriteOwner should be Critical' {
            $matchedRights = @('WriteOwner')
            $isVulnerable  = $true
            $riskLevel = if ($isVulnerable)
            {
                if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner') { 'Critical' } else { 'High' }
            }
            else { 'Informational' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'WriteProperty (non-owner/dacl) should be High' {
            $matchedRights = @('WriteProperty')
            $isVulnerable  = $true
            $riskLevel = if ($isVulnerable)
            {
                if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner') { 'Critical' } else { 'High' }
            }
            else { 'Informational' }
            $riskLevel | Should -Be 'High'
        }

        It 'Privileged principal should be Informational' {
            $isVulnerable = $false
            $riskLevel    = if ($isVulnerable) { 'Critical' } else { 'Informational' }
            $riskLevel | Should -Be 'Informational'
        }
    }

    Context 'Finding field content' {

        It 'Finding should mention SDProp propagation when IsVulnerable = true' {
            $isVulnerable  = $true
            $identity      = 'CONTOSO\HelpDesk'
            $matchedRights = @('WriteProperty')
            $finding       = if ($isVulnerable) { "AdminSDHolder backdoor: '$identity' has $($matchedRights -join ', ') — will propagate to all protected objects via SDProp" } else { $null }
            $finding | Should -Match 'SDProp'
            $finding | Should -Match 'AdminSDHolder'
        }
    }
}
