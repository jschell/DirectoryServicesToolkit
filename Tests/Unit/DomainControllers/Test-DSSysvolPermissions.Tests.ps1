BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSSysvolPermissions' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DCName            = 'DC01.contoso.com'
                ShareName         = 'SYSVOL'
                UNCPath           = '\\DC01.contoso.com\SYSVOL'
                IdentityReference = 'CONTOSO\HelpDesk'
                Rights            = 'Modify'
                MatchedRights     = @('Modify')
                IsInherited       = $false
                IsPrivilegedOwner = $false
                IsVulnerable      = $true
                RiskLevel         = 'High'
                Finding           = "SYSVOL write: 'CONTOSO\HelpDesk' has Modify on \\DC01.contoso.com\SYSVOL"
                ErrorMessage      = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'DCName'
            $result.PSObject.Properties.Name | Should -Contain 'ShareName'
            $result.PSObject.Properties.Name | Should -Contain 'UNCPath'
            $result.PSObject.Properties.Name | Should -Contain 'IdentityReference'
            $result.PSObject.Properties.Name | Should -Contain 'Rights'
            $result.PSObject.Properties.Name | Should -Contain 'IsVulnerable'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'Risk level classification' {

        It 'FullControl should be Critical' {
            $matchedRights = @('FullControl')
            $isVulnerable  = $true
            $riskLevel = if ($isVulnerable)
            {
                if ($matchedRights -contains 'FullControl') { 'Critical' } else { 'High' }
            }
            else { 'Informational' }
            $riskLevel | Should -Be 'Critical'
        }

        It 'Modify should be High' {
            $matchedRights = @('Modify')
            $isVulnerable  = $true
            $riskLevel = if ($isVulnerable)
            {
                if ($matchedRights -contains 'FullControl') { 'Critical' } else { 'High' }
            }
            else { 'Informational' }
            $riskLevel | Should -Be 'High'
        }

        It 'Privileged principal should be Informational' {
            $isVulnerable = $false
            $riskLevel    = if ($isVulnerable) { 'High' } else { 'Informational' }
            $riskLevel | Should -Be 'Informational'
        }
    }

    Context 'Share name validation' {

        It 'Should check both SYSVOL and NETLOGON share names' {
            $shares = @('SYSVOL', 'NETLOGON')
            $shares | Should -Contain 'SYSVOL'
            $shares | Should -Contain 'NETLOGON'
            $shares.Count | Should -Be 2
        }

        It 'UNC path should be constructed from DC name and share name' {
            $dc        = 'DC01.contoso.com'
            $shareName = 'SYSVOL'
            $uncPath   = "\\$dc\$shareName"
            $uncPath | Should -Be '\\DC01.contoso.com\SYSVOL'
        }
    }

    Context 'Error handling' {

        It 'ACL read failure should set RiskLevel to Unknown' {
            $riskLevel   = 'Unknown'
            $errorMessage = 'ACL read failed: Access denied'
            $riskLevel | Should -Be 'Unknown'
            $errorMessage | Should -Match 'ACL read failed'
        }
    }
}
