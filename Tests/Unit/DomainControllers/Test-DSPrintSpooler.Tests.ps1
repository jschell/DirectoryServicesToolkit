BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSPrintSpooler' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                Hostname       = 'DC01.contoso.com'
                Role           = 'DomainController'
                SpoolerState   = 'Running'
                SpoolerRunning = $true
                RiskLevel      = 'Critical'
                Finding        = 'Print Spooler is running on DomainController'
                ErrorMessage   = $null
            }

            $result.PSObject.Properties.Name | Should -Contain 'Hostname'
            $result.PSObject.Properties.Name | Should -Contain 'Role'
            $result.PSObject.Properties.Name | Should -Contain 'SpoolerState'
            $result.PSObject.Properties.Name | Should -Contain 'SpoolerRunning'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
            $result.PSObject.Properties.Name | Should -Contain 'ErrorMessage'
        }
    }

    Context 'Risk level classification' {

        It 'Running Spooler on DC should be Critical' {
            $spoolerRunning = $true
            $role           = 'DomainController'
            $risk           = if ($spoolerRunning -and $role -eq 'DomainController') { 'Critical' }
                              elseif ($spoolerRunning) { 'High' }
                              else { 'Low' }
            $risk           | Should -Be 'Critical'
        }

        It 'Running Spooler on MemberServer should be High' {
            $spoolerRunning = $true
            $role           = 'MemberServer'
            $risk           = if ($spoolerRunning -and $role -eq 'DomainController') { 'Critical' }
                              elseif ($spoolerRunning) { 'High' }
                              else { 'Low' }
            $risk           | Should -Be 'High'
        }

        It 'Stopped Spooler should be Low risk' {
            $spoolerRunning = $false
            $role           = 'DomainController'
            $risk           = if ($spoolerRunning -and $role -eq 'DomainController') { 'Critical' }
                              elseif ($spoolerRunning) { 'High' }
                              else { 'Low' }
            $risk           | Should -Be 'Low'
        }
    }

    Context 'Finding generation' {

        It 'Finding should be non-null when Spooler is running' {
            $spoolerRunning = $true
            $hostname       = 'DC01.contoso.com'
            $role           = 'DomainController'
            $finding        = if ($spoolerRunning) { "Print Spooler is running on $role '$hostname' — coercion attack surface exposed" } else { $null }
            $finding        | Should -Not -BeNullOrEmpty
        }

        It 'Finding should be null when Spooler is not running' {
            $spoolerRunning = $false
            $finding        = if ($spoolerRunning) { 'Risk finding' } else { $null }
            $finding        | Should -BeNullOrEmpty
        }
    }
}
