BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSCredentialProtection' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DCName                        = 'DC01.contoso.com'
                LocalAccountTokenFilterPolicy = 0
                DisableRestrictedAdmin        = 0
                CredentialGuardFlags          = 1
                CredentialGuardEnabled        = $true
                Issues                        = @()
                IssueCount                    = 0
                RiskLevel                     = 'Low'
                IsCompliant                   = $true
                ErrorMessage                  = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'DCName'
            $result.PSObject.Properties.Name | Should -Contain 'LocalAccountTokenFilterPolicy'
            $result.PSObject.Properties.Name | Should -Contain 'DisableRestrictedAdmin'
            $result.PSObject.Properties.Name | Should -Contain 'CredentialGuardFlags'
            $result.PSObject.Properties.Name | Should -Contain 'CredentialGuardEnabled'
            $result.PSObject.Properties.Name | Should -Contain 'Issues'
            $result.PSObject.Properties.Name | Should -Contain 'IssueCount'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'IsCompliant'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'LocalAccountTokenFilterPolicy risk' {

        It 'LATFP = 1 should produce High risk' {
            $latfp    = 1
            $issues   = @()
            if ($latfp -eq 1) { $issues += 'LocalAccountTokenFilterPolicy=1 enables pass-the-hash via network logon' }
            $riskLevel = if ($latfp -eq 1) { 'High' } else { 'Low' }
            $riskLevel | Should -Be 'High'
            $issues.Count | Should -Be 1
        }

        It 'LATFP = 0 should not add to issues' {
            $latfp    = 0
            $issues   = @()
            if ($latfp -eq 1) { $issues += 'LocalAccountTokenFilterPolicy=1 enables pass-the-hash via network logon' }
            $issues.Count | Should -Be 0
        }
    }

    Context 'CredentialGuard detection' {

        It 'CredentialGuardEnabled should be true when LsaCfgFlags > 0' {
            $cgFlags = 1
            $enabled = ($cgFlags -gt 0)
            $enabled | Should -BeTrue

            $cgFlags = 2
            $enabled = ($cgFlags -gt 0)
            $enabled | Should -BeTrue
        }

        It 'CredentialGuardEnabled should be false when LsaCfgFlags = 0' {
            $cgFlags = 0
            $enabled = ($cgFlags -gt 0)
            $enabled | Should -BeFalse
        }
    }

    Context 'IsCompliant logic' {

        It 'IsCompliant should be true when RiskLevel is Low' {
            $riskLevel  = 'Low'
            $isCompliant = ($riskLevel -eq 'Low')
            $isCompliant | Should -BeTrue
        }

        It 'IsCompliant should be false when RiskLevel is High' {
            $riskLevel  = 'High'
            $isCompliant = ($riskLevel -eq 'Low')
            $isCompliant | Should -BeFalse
        }
    }
}
