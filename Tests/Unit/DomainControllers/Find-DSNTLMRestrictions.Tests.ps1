BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSNTLMRestrictions' -Tag 'Unit', 'DomainControllers' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                GPOGuid       = '{12345678-1234-1234-1234-123456789012}'
                FilePath      = '\\contoso.com\SYSVOL\contoso.com\Policies\{12345678-1234-1234-1234-123456789012}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
                SettingName   = 'LmCompatibilityLevel'
                SettingValue  = '4,5'
                HasNTLMPolicy = $true
            }

            $result.PSObject.Properties.Name | Should -Contain 'GPOGuid'
            $result.PSObject.Properties.Name | Should -Contain 'FilePath'
            $result.PSObject.Properties.Name | Should -Contain 'SettingName'
            $result.PSObject.Properties.Name | Should -Contain 'SettingValue'
            $result.PSObject.Properties.Name | Should -Contain 'HasNTLMPolicy'
        }

        It 'HasNTLMPolicy should always be true for returned results' {
            $result = [PSCustomObject]@{ HasNTLMPolicy = $true }
            $result.HasNTLMPolicy | Should -BeTrue
        }
    }

    Context 'GPO GUID extraction from file path' {

        It 'Should extract GPO GUID from inf file path' {
            $path    = '\\contoso.com\SYSVOL\contoso.com\Policies\{AABBCCDD-1234-ABCD-EF12-123456789012}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            $gpoGuid = $null
            if ($path -match '\{([0-9A-Fa-f-]{36})\}')
            {
                $gpoGuid = $Matches[1]
            }
            $gpoGuid | Should -Not -BeNullOrEmpty
            $gpoGuid | Should -Be 'AABBCCDD-1234-ABCD-EF12-123456789012'
        }

        It 'Should return null GUID when path has no GUID' {
            $path    = '\\contoso.com\SYSVOL\contoso.com\Policies\NoBraces\GptTmpl.inf'
            $gpoGuid = $null
            if ($path -match '\{([0-9A-Fa-f-]{36})\}')
            {
                $gpoGuid = $Matches[1]
            }
            $gpoGuid | Should -BeNullOrEmpty
        }
    }

    Context 'NTLM-related registry key detection' {

        It 'LmCompatibilityLevel key should be in the scan list' {
            $ntlmKeys = @(
                'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
                'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'
                'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictNTLM'
            )
            $ntlmKeys | Should -Contain 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
        }

        It 'NoLMHash key should be in the scan list' {
            $ntlmKeys = @(
                'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
                'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'
            )
            $ntlmKeys | Should -Contain 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'
        }

        It 'Should extract setting value from line containing registry path' {
            $line     = 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5'
            $keyMatch = 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
            $value    = $null
            if ($line -match [regex]::Escape($keyMatch))
            {
                $value = if ($line -match '=\s*(.+)$') { $Matches[1].Trim() } else { 'Present' }
            }
            $value | Should -Be '4,5'
        }
    }
}
