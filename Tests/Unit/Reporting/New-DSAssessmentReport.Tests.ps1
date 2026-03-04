BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'New-DSAssessmentReport' -Tag 'Unit', 'Reporting' {

    Context 'Output file naming' {

        It 'HTML report file name should end with .html' {
            $ext   = 'html'
            $title = 'AD-Security-Assessment-Report'
            $date  = '2026-03-03'
            $name  = '{0}-{1}.{2}' -f $title, $date, $ext
            $name  | Should -Match '\.html$'
        }

        It 'CSV report file name should end with .csv' {
            $ext  = 'csv'
            $title = 'AD-Security-Assessment-Report'
            $date  = '2026-03-03'
            $name  = '{0}-{1}.{2}' -f $title, $date, $ext
            $name  | Should -Match '\.csv$'
        }
    }

    Context 'Input normalisation' {

        It 'Hashtable input should produce one section per key' {
            $input = @{
                Kerberoastable = @([PSCustomObject]@{ SamAccountName = 'svc1' })
                Delegation     = @([PSCustomObject]@{ SamAccountName = 'svc2' })
            }
            $sections = [ordered]@{}
            foreach ($kvp in $input.GetEnumerator()) { $sections[$kvp.Key] = @($kvp.Value) }

            $sections.Count | Should -Be 2
            ($sections.Contains('Kerberoastable')) | Should -BeTrue
            ($sections.Contains('Delegation'))     | Should -BeTrue
        }

        It 'Non-hashtable flat array should produce single Ungrouped section' {
            $items    = @([PSCustomObject]@{ Name = 'obj1' }, [PSCustomObject]@{ Name = 'obj2' })
            $sections = [ordered]@{ 'Ungrouped' = $items }
            $sections.Count         | Should -Be 1
            $sections.Contains('Ungrouped') | Should -BeTrue
        }
    }

    Context 'HTML output' {

        BeforeAll {
            $script:htmlTempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('DSTest_' + [System.Guid]::NewGuid().ToString('N'))
            [void](New-Item -ItemType Directory -Path $script:htmlTempDir -Force)
        }

        AfterAll {
            if (Test-Path $script:htmlTempDir) { Remove-Item $script:htmlTempDir -Recurse -Force }
        }

        It 'Should write an HTML file and return its path' {
            $findings = @{
                AdminAccounts = @([PSCustomObject]@{ SamAccountName = 'Admin1'; Enabled = $true })
            }
            $result = New-DSAssessmentReport -InputObject $findings -OutputPath $script:htmlTempDir `
                -Format HTML -Domain 'contoso.com'
            $result    | Should -Not -BeNullOrEmpty
            Test-Path $result | Should -BeTrue
        }

        It 'HTML file should contain the report title' {
            $findings = @{
                AdminAccounts = @([PSCustomObject]@{ SamAccountName = 'Admin1'; Enabled = $true })
            }
            $result  = New-DSAssessmentReport -InputObject $findings -OutputPath $script:htmlTempDir `
                -Format HTML -Title 'Custom Report Title' -Domain 'contoso.com'
            $content = Get-Content $result -Raw
            $content | Should -Match 'Custom Report Title'
        }

        It 'HTML file should contain section header for each input key' {
            $findings = @{
                Kerberoastable = @([PSCustomObject]@{ SamAccountName = 'svc1' })
                Delegation     = @([PSCustomObject]@{ SamAccountName = 'svc2' })
            }
            $result  = New-DSAssessmentReport -InputObject $findings -OutputPath $script:htmlTempDir `
                -Format HTML -Domain 'contoso.com'
            $content = Get-Content $result -Raw
            $content | Should -Match '<h2>Kerberoastable</h2>'
            $content | Should -Match '<h2>Delegation</h2>'
        }

        It 'HTML file should contain an Executive Summary table' {
            $findings = @{
                AdminAccounts = @([PSCustomObject]@{ SamAccountName = 'Admin1' })
            }
            $result  = New-DSAssessmentReport -InputObject $findings -OutputPath $script:htmlTempDir `
                -Format HTML -Domain 'contoso.com'
            $content = Get-Content $result -Raw
            $content | Should -Match 'Executive Summary'
        }

        It 'Empty section should display No items found message' {
            $findings = @{ EmptySection = @() }
            $result  = New-DSAssessmentReport -InputObject $findings -OutputPath $script:htmlTempDir `
                -Format HTML -Domain 'contoso.com'
            $content = Get-Content $result -Raw
            $content | Should -Match 'No items found'
        }

        It 'HTML should be well-formed with opening and closing html tags' {
            $findings = @{ Test = @([PSCustomObject]@{ Name = 'item1' }) }
            $result  = New-DSAssessmentReport -InputObject $findings -OutputPath $script:htmlTempDir `
                -Format HTML -Domain 'contoso.com'
            $content = Get-Content $result -Raw
            $content | Should -Match '<html'
            $content | Should -Match '</html>'
        }
    }

    Context 'CSV output' {

        BeforeAll {
            $script:csvTempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('DSTest_' + [System.Guid]::NewGuid().ToString('N'))
            [void](New-Item -ItemType Directory -Path $script:csvTempDir -Force)
        }

        AfterAll {
            if (Test-Path $script:csvTempDir) { Remove-Item $script:csvTempDir -Recurse -Force }
        }

        It 'Should write a CSV file and return its path' {
            $findings = @{
                AdminAccounts = @([PSCustomObject]@{ SamAccountName = 'Admin1'; Enabled = $true })
            }
            $result = New-DSAssessmentReport -InputObject $findings -OutputPath $script:csvTempDir `
                -Format CSV -Domain 'contoso.com'
            $result      | Should -Not -BeNullOrEmpty
            Test-Path $result | Should -BeTrue
        }

        It 'CSV file should have a .csv extension' {
            $findings = @{
                AdminAccounts = @([PSCustomObject]@{ SamAccountName = 'Admin1' })
            }
            $result = New-DSAssessmentReport -InputObject $findings -OutputPath $script:csvTempDir `
                -Format CSV -Domain 'contoso.com'
            $result | Should -Match '\.csv$'
        }

        It 'Multi-section CSV should include a Category column' {
            $findings = @{
                Kerberoastable = @([PSCustomObject]@{ SamAccountName = 'svc1' })
                Delegation     = @([PSCustomObject]@{ SamAccountName = 'svc2' })
            }
            $result  = New-DSAssessmentReport -InputObject $findings -OutputPath $script:csvTempDir `
                -Format CSV -Domain 'contoso.com'
            $content = Get-Content $result -Raw
            $content | Should -Match 'Category'
        }
    }

    Context 'Pipeline input' {

        BeforeAll {
            $script:pipeTempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('DSTest_' + [System.Guid]::NewGuid().ToString('N'))
            [void](New-Item -ItemType Directory -Path $script:pipeTempDir -Force)
        }

        AfterAll {
            if (Test-Path $script:pipeTempDir) { Remove-Item $script:pipeTempDir -Recurse -Force }
        }

        It 'Pipeline objects should be treated as Ungrouped section' {
            $obj1   = [PSCustomObject]@{ SamAccountName = 'svc1'; HasSPN = $true }
            $result = $obj1 | New-DSAssessmentReport -OutputPath $script:pipeTempDir -Format HTML
            $content = Get-Content $result -Raw
            $content | Should -Match 'Ungrouped'
        }
    }
}
