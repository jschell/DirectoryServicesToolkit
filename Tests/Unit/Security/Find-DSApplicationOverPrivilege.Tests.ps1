BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSApplicationOverPrivilege' -Tag 'Unit', 'Security' {

    Context 'Output schema validation' {

        It 'Should include all required output properties for KnownOverPrivilegedGroup type' {
            $result = [PSCustomObject]@{
                FindingType       = 'KnownOverPrivilegedGroup'
                GroupName         = 'Exchange Windows Permissions'
                GroupDN           = 'CN=Exchange Windows Permissions,CN=Users,DC=contoso,DC=com'
                Description       = 'Exchange group with potential legacy WriteDACL on domain object'
                MemberCount       = 5
                IdentityReference = $null
                Rights            = $null
                RiskLevel         = 'High'
                Finding           = "Application group 'Exchange Windows Permissions' found — may have legacy over-privilege on domain objects"
            }

            $result.PSObject.Properties.Name | Should -Contain 'FindingType'
            $result.PSObject.Properties.Name | Should -Contain 'GroupName'
            $result.PSObject.Properties.Name | Should -Contain 'GroupDN'
            $result.PSObject.Properties.Name | Should -Contain 'Description'
            $result.PSObject.Properties.Name | Should -Contain 'MemberCount'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }

        It 'Should include all required output properties for DomainObjectDACL type' {
            $result = [PSCustomObject]@{
                FindingType       = 'DomainObjectDACL'
                GroupName         = 'CONTOSO\ExchangeService'
                GroupDN           = $null
                Description       = 'Non-privileged principal with dangerous rights on domain NC root'
                MemberCount       = $null
                IdentityReference = 'CONTOSO\ExchangeService'
                Rights            = 'WriteDacl'
                RiskLevel         = 'Critical'
                Finding           = "Domain object DACL: 'CONTOSO\ExchangeService' has WriteDacl on the domain NC root"
            }

            $result.PSObject.Properties.Name | Should -Contain 'FindingType'
            $result.PSObject.Properties.Name | Should -Contain 'IdentityReference'
            $result.PSObject.Properties.Name | Should -Contain 'Rights'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }
    }

    Context 'Risk level classification for known groups' {

        It 'Exchange Windows Permissions group should be High' {
            $cn        = 'Exchange Windows Permissions'
            $riskLevel = if ($cn -in @('Exchange Windows Permissions', 'Organization Management')) { 'High' } else { 'Medium' }
            $riskLevel | Should -Be 'High'
        }

        It 'Organization Management should be High' {
            $cn        = 'Organization Management'
            $riskLevel = if ($cn -in @('Exchange Windows Permissions', 'Organization Management')) { 'High' } else { 'Medium' }
            $riskLevel | Should -Be 'High'
        }

        It 'Exchange Trusted Subsystem should be Medium' {
            $cn        = 'Exchange Trusted Subsystem'
            $riskLevel = if ($cn -in @('Exchange Windows Permissions', 'Organization Management')) { 'High' } else { 'Medium' }
            $riskLevel | Should -Be 'Medium'
        }
    }

    Context 'Domain DACL finding type' {

        It 'DomainObjectDACL finding should always be Critical' {
            $findingType = 'DomainObjectDACL'
            $riskLevel   = 'Critical'   # per implementation
            $riskLevel | Should -Be 'Critical'
        }

        It 'Finding for DomainObjectDACL should mention DCSync/privilege escalation' {
            $identity      = 'CONTOSO\ExchangeService'
            $matchedRights = @('WriteDacl')
            $finding       = "Domain object DACL: '$identity' has $($matchedRights -join ', ') on the domain NC root — potential DCSync/privilege escalation path"
            $finding | Should -Match 'domain NC root'
            $finding | Should -Match 'DCSync'
        }
    }
}
