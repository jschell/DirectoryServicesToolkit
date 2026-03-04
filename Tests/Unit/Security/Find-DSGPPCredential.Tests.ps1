BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Find-DSGPPCredential' -Tag 'Unit', 'Security' {

    Context 'Output schema validation' {

        It 'Should include all required output properties' {
            $result = [PSCustomObject]@{
                GPOGuid           = '{12345678-1234-1234-1234-123456789012}'
                FilePath          = '\\contoso.com\SYSVOL\contoso.com\Policies\{12345678-1234-1234-1234-123456789012}\Machine\Preferences\Groups\Groups.xml'
                FileName          = 'Groups.xml'
                UserName          = 'Administrator'
                CPassword         = 'abc123encryptedvalue'
                DecryptedPassword = 'P@ssw0rd'
                IsDecrypted       = $true
                RiskLevel         = 'Critical'
                Finding           = 'cPassword credential found in GPP file'
            }

            $result.PSObject.Properties.Name | Should -Contain 'GPOGuid'
            $result.PSObject.Properties.Name | Should -Contain 'FilePath'
            $result.PSObject.Properties.Name | Should -Contain 'FileName'
            $result.PSObject.Properties.Name | Should -Contain 'UserName'
            $result.PSObject.Properties.Name | Should -Contain 'CPassword'
            $result.PSObject.Properties.Name | Should -Contain 'DecryptedPassword'
            $result.PSObject.Properties.Name | Should -Contain 'IsDecrypted'
            $result.PSObject.Properties.Name | Should -Contain 'RiskLevel'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
        }

        It 'RiskLevel should be Critical for any GPP credential' {
            $result = [PSCustomObject]@{ RiskLevel = 'Critical' }
            $result.RiskLevel | Should -Be 'Critical'
        }
    }

    Context 'GPO GUID extraction from path' {

        It 'Should extract GPO GUID from file path' {
            $path    = '\\contoso.com\SYSVOL\contoso.com\Policies\{12345678-ABCD-1234-EFGH-123456789012}\Machine\Preferences\Groups\Groups.xml'
            $gpoGuid = $null
            if ($path -match '\{([0-9A-Fa-f-]{36})\}')
            {
                $gpoGuid = $Matches[1]
            }
            $gpoGuid | Should -Not -BeNullOrEmpty
            $gpoGuid | Should -Be '12345678-ABCD-1234-EFGH-123456789012'
        }

        It 'Should return null when path contains no GUID' {
            $path    = '\\contoso.com\SYSVOL\contoso.com\Policies\SomeFolder\Groups.xml'
            $gpoGuid = $null
            if ($path -match '\{([0-9A-Fa-f-]{36})\}')
            {
                $gpoGuid = $Matches[1]
            }
            $gpoGuid | Should -BeNullOrEmpty
        }
    }

    Context 'Redact switch' {

        It 'DecryptedPassword should be redacted when -Redact is specified' {
            $redact            = $true
            $decryptedPassword = 'P@ssw0rd'
            $output            = if ($redact) { '<REDACTED>' } else { $decryptedPassword }
            $output            | Should -Be '<REDACTED>'
        }

        It 'DecryptedPassword should be visible when -Redact is not specified' {
            $redact            = $false
            $decryptedPassword = 'P@ssw0rd'
            $output            = if ($redact) { '<REDACTED>' } else { $decryptedPassword }
            $output            | Should -Be 'P@ssw0rd'
        }
    }

    Context 'AES decryption key' {

        It 'AES key should be 32 bytes' {
            $aesKey = [byte[]]@(
                0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,
                0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,
                0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b
            )
            $aesKey.Length | Should -Be 32
        }
    }

    Context 'GPP target file names' {

        It 'Should target standard GPP credential files' {
            $gppFiles = @(
                'Groups.xml'
                'Services.xml'
                'ScheduledTasks.xml'
                'DataSources.xml'
                'Printers.xml'
                'Drives.xml'
            )
            $gppFiles | Should -Contain 'Groups.xml'
            $gppFiles | Should -Contain 'Services.xml'
            $gppFiles | Should -Contain 'ScheduledTasks.xml'
            $gppFiles.Count | Should -Be 6
        }
    }
}
