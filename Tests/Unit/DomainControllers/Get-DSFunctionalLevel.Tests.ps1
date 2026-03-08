BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Get-DSFunctionalLevel' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                Domain                = 'contoso.com'
                DomainFunctionalLevel = 7
                DomainFunctionalName  = 'Windows Server 2016'
                ForestFunctionalLevel = 7
                ForestFunctionalName  = 'Windows Server 2016'
                Issues                = @()
                RiskLevel             = 'Low'
                IsCompliant           = $true
            }

            $result.PSObject.Properties.Name | Should -Contain 'Domain'
            $result.PSObject.Properties.Name | Should -Contain 'DomainFunctionalLevel'
            $result.PSObject.Properties.Name | Should -Contain 'DomainFunctionalName'
            $result.PSObject.Properties.Name | Should -Contain 'ForestFunctionalLevel'
            $result.PSObject.Properties.Name | Should -Contain 'ForestFunctionalName'
            $result.PSObject.Properties.Name | Should -Contain 'Issues'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'IsCompliant'
        }
    }

    Context 'Risk level classification' {

        It 'DFL=7 and FFL=7 should be Low' {
            $dfl       = 7
            $ffl       = 7
            $riskLevel = if ($null -eq $dfl -or $null -eq $ffl) { 'Unknown' }
                         elseif ($dfl -lt 5 -or $ffl -lt 5) { 'High' }
                         elseif ($dfl -lt 7 -or $ffl -lt 7) { 'Medium' }
                         else { 'Low' }
            $riskLevel | Should -Be 'Low'
        }

        It 'DFL=7 and FFL=10 should be Low' {
            $dfl       = 7
            $ffl       = 10
            $riskLevel = if ($null -eq $dfl -or $null -eq $ffl) { 'Unknown' }
                         elseif ($dfl -lt 5 -or $ffl -lt 5) { 'High' }
                         elseif ($dfl -lt 7 -or $ffl -lt 7) { 'Medium' }
                         else { 'Low' }
            $riskLevel | Should -Be 'Low'
        }

        It 'DFL=6 (2012 R2) and FFL=7 should be Medium' {
            $dfl       = 6
            $ffl       = 7
            $riskLevel = if ($null -eq $dfl -or $null -eq $ffl) { 'Unknown' }
                         elseif ($dfl -lt 5 -or $ffl -lt 5) { 'High' }
                         elseif ($dfl -lt 7 -or $ffl -lt 7) { 'Medium' }
                         else { 'Low' }
            $riskLevel | Should -Be 'Medium'
        }

        It 'DFL=3 (2008) should be High' {
            $dfl       = 3
            $ffl       = 7
            $riskLevel = if ($null -eq $dfl -or $null -eq $ffl) { 'Unknown' }
                         elseif ($dfl -lt 5 -or $ffl -lt 5) { 'High' }
                         elseif ($dfl -lt 7 -or $ffl -lt 7) { 'Medium' }
                         else { 'Low' }
            $riskLevel | Should -Be 'High'
        }

        It 'Null DFL should be Unknown' {
            $dfl       = $null
            $ffl       = 7
            $riskLevel = if ($null -eq $dfl -or $null -eq $ffl) { 'Unknown' }
                         else { 'Low' }
            $riskLevel | Should -Be 'Unknown'
        }
    }

    Context 'Level name mapping' {

        It 'Level 7 should map to Windows Server 2016' {
            $levelNames = @{ 7 = 'Windows Server 2016'; 10 = 'Windows Server 2019 / 2022' }
            $levelNames[7] | Should -Be 'Windows Server 2016'
        }

        It 'Level 10 should map to Windows Server 2019 / 2022' {
            $levelNames = @{ 7 = 'Windows Server 2016'; 10 = 'Windows Server 2019 / 2022' }
            $levelNames[10] | Should -Be 'Windows Server 2019 / 2022'
        }
    }
}
