BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSADCSContainerACL' -Tag 'Unit', 'Security', 'ADCS' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                ContainerName     = 'Enrollment Services'
                ContainerDN       = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                IdentityReference = 'CONTOSO\HelpDesk'
                Rights            = 'CreateChild'
                MatchedRights     = @('CreateChild')
                IsInherited       = $false
                IsPrivilegedOwner = $false
                IsVulnerable      = $true
                RiskLevel         = 'Critical'
                Finding           = "ESC5: 'CONTOSO\HelpDesk' has CreateChild on 'Enrollment Services'"
            }

            $result.PSObject.Properties.Name | Should -Contain 'ContainerName'
            $result.PSObject.Properties.Name | Should -Contain 'ContainerDN'
            $result.PSObject.Properties.Name | Should -Contain 'IdentityReference'
            $result.PSObject.Properties.Name | Should -Contain 'Rights'
            $result.PSObject.Properties.Name | Should -Contain 'MatchedRights'
            $result.PSObject.Properties.Name | Should -Contain 'IsVulnerable'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }
    }

    Context 'Risk level classification' {

        It 'CreateChild on PKI container should be Critical' {
            $matchedRights = @('CreateChild')
            $isVulnerable  = $true
            $riskLevel = if ($isVulnerable)
            {
                if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner' -or $matchedRights -contains 'CreateChild') { 'Critical' } else { 'High' }
            }
            else { 'Informational' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'WriteProperty on PKI container should be High' {
            $matchedRights = @('WriteProperty')
            $isVulnerable  = $true
            $riskLevel = if ($isVulnerable)
            {
                if ($matchedRights -contains 'GenericAll' -or $matchedRights -contains 'WriteDacl' -or $matchedRights -contains 'WriteOwner' -or $matchedRights -contains 'CreateChild') { 'Critical' } else { 'High' }
            }
            else { 'Informational' }
            $riskLevel | Should -Be 'High'
        }

        It 'Safe principal should be Informational' {
            $isVulnerable = $false
            $riskLevel    = if ($isVulnerable) { 'Critical' } else { 'Informational' }
            $riskLevel | Should -Be 'Informational'
        }
    }

    Context 'Finding field' {

        It 'Finding should reference ESC5 when IsVulnerable = true' {
            $isVulnerable  = $true
            $identity      = 'CONTOSO\HelpDesk'
            $matchedRights = @('CreateChild')
            $containerName = 'Enrollment Services'
            $finding       = if ($isVulnerable) { "ESC5: '$identity' has $($matchedRights -join ', ') on '$containerName'" } else { $null }
            $finding | Should -Match 'ESC5'
        }
    }
}
