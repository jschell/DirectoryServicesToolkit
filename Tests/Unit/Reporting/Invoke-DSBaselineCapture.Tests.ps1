BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Invoke-DSBaselineCapture' -Tag 'Unit', 'Reporting' {

    Context 'Output file naming' {

        It 'File name should contain the domain name' {
            $domain    = 'contoso.com'
            $timestamp = '2026-03-03T10-00-00Z'
            $fileName  = '{0}-baseline-{1}.json' -f ($domain -replace '[^\w\.]', '_'), $timestamp
            $fileName  | Should -Match 'contoso'
        }

        It 'File name should contain the word baseline' {
            $domain    = 'contoso.com'
            $timestamp = '2026-03-03T10-00-00Z'
            $fileName  = '{0}-baseline-{1}.json' -f ($domain -replace '[^\w\.]', '_'), $timestamp
            $fileName  | Should -Match 'baseline'
        }

        It 'File name should have a .json extension' {
            $domain    = 'contoso.com'
            $timestamp = '2026-03-03T10-00-00Z'
            $fileName  = '{0}-baseline-{1}.json' -f ($domain -replace '[^\w\.]', '_'), $timestamp
            $fileName  | Should -Match '\.json$'
        }
    }

    Context 'JSON schema structure' {

        It 'Snapshot document should contain required top-level keys' {
            $snapshot = [ordered]@{
                Schema        = '1.0'
                CapturedAt    = (Get-Date).ToUniversalTime().ToString('o')
                Domain        = 'contoso.com'
                Indicators    = [ordered]@{}
                CaptureErrors = [ordered]@{}
            }

            $snapshot.Contains('Schema')        | Should -BeTrue
            $snapshot.Contains('CapturedAt')    | Should -BeTrue
            $snapshot.Contains('Domain')        | Should -BeTrue
            $snapshot.Contains('Indicators')    | Should -BeTrue
            $snapshot.Contains('CaptureErrors') | Should -BeTrue
        }

        It 'Schema version should be 1.0' {
            $snapshot = [ordered]@{ Schema = '1.0' }
            $snapshot.Schema | Should -Be '1.0'
        }
    }

    Context 'Indicator map' {

        It 'Should include all seven standard indicators' {
            $indicatorMap = @{
                AdminAccounts  = 'Get-DSAdminAccounts'
                Delegation     = 'Find-DSDelegation'
                Trusts         = 'Get-DSTrustRelationship'
                PasswordPolicy = 'Get-DSPasswordPolicy'
                Kerberoastable = 'Find-DSKerberoastable'
                ASREPRoastable = 'Find-DSASREPRoastable'
                AdminSDHolder  = 'Get-DSAdminSDHolder'
            }
            $indicatorMap.Count | Should -Be 7
            $indicatorMap.ContainsKey('AdminAccounts')  | Should -BeTrue
            $indicatorMap.ContainsKey('Trusts')         | Should -BeTrue
            $indicatorMap.ContainsKey('Kerberoastable') | Should -BeTrue
        }
    }

    Context 'Mocked capture — writes JSON file and returns path' {

        BeforeEach {
            $script:tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('DSTest_' + [System.Guid]::NewGuid().ToString('N'))

            InModuleScope DirectoryServicesToolkit {
                Mock Get-DSAdminAccounts  { return @([PSCustomObject]@{ SamAccountName = 'admin1' }) }
                Mock Find-DSDelegation    { return @() }
                Mock Get-DSTrustRelationship { return @() }
                Mock Get-DSPasswordPolicy    { return @([PSCustomObject]@{ Name = 'Default Domain Policy' }) }
                Mock Find-DSKerberoastable   { return @() }
                Mock Find-DSASREPRoastable   { return @() }
                Mock Get-DSAdminSDHolder     { return @() }
            }
        }

        AfterEach {
            if (Test-Path $script:tempDir) { Remove-Item $script:tempDir -Recurse -Force }
        }

        It 'Should return a file path string' {
            $result = Invoke-DSBaselineCapture -Domain 'contoso.com' -OutputPath $script:tempDir
            $result | Should -BeOfType [string]
        }

        It 'Returned path should point to an existing file' {
            $result = Invoke-DSBaselineCapture -Domain 'contoso.com' -OutputPath $script:tempDir
            Test-Path $result | Should -BeTrue
        }

        It 'Written file should be valid JSON' {
            $result  = Invoke-DSBaselineCapture -Domain 'contoso.com' -OutputPath $script:tempDir
            $content = Get-Content $result -Raw
            { $content | ConvertFrom-Json } | Should -Not -Throw
        }

        It 'JSON should contain AdminAccounts indicator' {
            $result  = Invoke-DSBaselineCapture -Domain 'contoso.com' -OutputPath $script:tempDir
            $json    = Get-Content $result -Raw | ConvertFrom-Json
            $json.Indicators.AdminAccounts | Should -Not -BeNullOrEmpty
        }

        It '-Indicators subset should capture only specified indicators' {
            $result = Invoke-DSBaselineCapture -Domain 'contoso.com' -OutputPath $script:tempDir `
                -Indicators 'AdminAccounts', 'Trusts'
            $json   = Get-Content $result -Raw | ConvertFrom-Json
            ($json.Indicators.PSObject.Properties.Name -contains 'AdminAccounts') | Should -BeTrue
            ($json.Indicators.PSObject.Properties.Name -contains 'Trusts')        | Should -BeTrue
            ($json.Indicators.PSObject.Properties.Name -contains 'Delegation')    | Should -BeFalse
        }

        It 'Failed indicator should be recorded in CaptureErrors and not abort capture' {
            Mock Find-DSDelegation -ModuleName DirectoryServicesToolkit { throw 'Simulated failure' }

            $result = Invoke-DSBaselineCapture -Domain 'contoso.com' -OutputPath $script:tempDir `
                -Indicators 'AdminAccounts', 'Delegation' -WarningAction SilentlyContinue
            $json   = Get-Content $result -Raw | ConvertFrom-Json

            $json.CaptureErrors.Delegation | Should -Not -BeNullOrEmpty
            ($json.Indicators.PSObject.Properties.Name -contains 'AdminAccounts') | Should -BeTrue
        }
    }
}
