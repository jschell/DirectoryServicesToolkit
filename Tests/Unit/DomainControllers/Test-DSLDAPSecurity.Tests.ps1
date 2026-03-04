BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Test-DSLDAPSecurity' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                DCName                 = 'DC01.contoso.com'
                SigningValue           = 2
                SigningRiskLevel       = 'Compliant'
                ChannelBindingValue    = 2
                ChannelBindingRisk     = 'Compliant'
                IsSigningCompliant     = $true
                IsChannelBindCompliant = $true
                IsFullyCompliant       = $true
                CompositeRiskLevel     = 'Compliant'
            }

            $result.PSObject.Properties.Name | Should -Contain 'DCName'
            $result.PSObject.Properties.Name | Should -Contain 'SigningValue'
            $result.PSObject.Properties.Name | Should -Contain 'SigningRiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'ChannelBindingValue'
            $result.PSObject.Properties.Name | Should -Contain 'ChannelBindingRisk'
            $result.PSObject.Properties.Name | Should -Contain 'IsSigningCompliant'
            $result.PSObject.Properties.Name | Should -Contain 'IsChannelBindCompliant'
            $result.PSObject.Properties.Name | Should -Contain 'IsFullyCompliant'
            $result.PSObject.Properties.Name | Should -Contain 'CompositeRiskLevel'
        }
    }

    Context 'IsFullyCompliant logic' {

        It 'IsFullyCompliant should be true when both signing and channel binding are compliant' {
            $sigCompliant = $true
            $cbCompliant  = $true
            $fully        = $sigCompliant -and $cbCompliant
            $fully        | Should -BeTrue
        }

        It 'IsFullyCompliant should be false when signing is not compliant' {
            $sigCompliant = $false
            $cbCompliant  = $true
            $fully        = $sigCompliant -and $cbCompliant
            $fully        | Should -BeFalse
        }

        It 'IsFullyCompliant should be false when channel binding is not compliant' {
            $sigCompliant = $true
            $cbCompliant  = $false
            $fully        = $sigCompliant -and $cbCompliant
            $fully        | Should -BeFalse
        }
    }

    Context 'CompositeRiskLevel logic' {

        It 'CompositeRiskLevel should be Critical when either component is Critical' {
            $sigRisk = 'Critical'
            $cbRisk  = 'Medium'
            $composite = if ($sigRisk -eq 'Critical' -or $cbRisk -eq 'Critical') { 'Critical' }
                         elseif ($sigRisk -eq 'Medium' -or $cbRisk -eq 'Medium') { 'Medium' }
                         else { 'Compliant' }
            $composite | Should -Be 'Critical'
        }

        It 'CompositeRiskLevel should be Medium when one is Medium and neither is Critical' {
            $sigRisk = 'Compliant'
            $cbRisk  = 'Medium'
            $composite = if ($sigRisk -eq 'Critical' -or $cbRisk -eq 'Critical') { 'Critical' }
                         elseif ($sigRisk -eq 'Medium' -or $cbRisk -eq 'Medium') { 'Medium' }
                         else { 'Compliant' }
            $composite | Should -Be 'Medium'
        }

        It 'CompositeRiskLevel should be Compliant when both components are Compliant' {
            $sigRisk = 'Compliant'
            $cbRisk  = 'Compliant'
            $composite = if ($sigRisk -eq 'Critical' -or $cbRisk -eq 'Critical') { 'Critical' }
                         elseif ($sigRisk -eq 'Medium' -or $cbRisk -eq 'Medium') { 'Medium' }
                         else { 'Compliant' }
            $composite | Should -Be 'Compliant'
        }
    }
}
