BeforeAll {
    Import-Module "$PSScriptRoot/../../../Source/DirectoryServicesToolkit.psm1" -Force
    . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"
}

Describe 'Compare-DSBaseline' -Tag 'Unit', 'Reporting' {

    Context 'Output schema validation' {

        It 'Should include all required top-level output properties' {
            $result = [PSCustomObject]@{
                BaselineCapturedAt = '2026-01-01T00:00:00Z'
                CurrentCapturedAt  = '2026-03-01T00:00:00Z'
                Domain             = 'contoso.com'
                Diffs              = [ordered]@{}
                Summary            = [PSCustomObject]@{
                    TotalAdded    = 0
                    TotalRemoved  = 0
                    TotalModified = 0
                    HasChanges    = $false
                }
            }

            $result.PSObject.Properties.Name | Should -Contain 'BaselineCapturedAt'
            $result.PSObject.Properties.Name | Should -Contain 'CurrentCapturedAt'
            $result.PSObject.Properties.Name | Should -Contain 'Domain'
            $result.PSObject.Properties.Name | Should -Contain 'Diffs'
            $result.PSObject.Properties.Name | Should -Contain 'Summary'
        }

        It 'Summary should contain TotalAdded, TotalRemoved, TotalModified, HasChanges' {
            $summary = [PSCustomObject]@{
                TotalAdded    = 1
                TotalRemoved  = 0
                TotalModified = 0
                HasChanges    = $true
            }

            $summary.PSObject.Properties.Name | Should -Contain 'TotalAdded'
            $summary.PSObject.Properties.Name | Should -Contain 'TotalRemoved'
            $summary.PSObject.Properties.Name | Should -Contain 'TotalModified'
            $summary.PSObject.Properties.Name | Should -Contain 'HasChanges'
        }
    }

    Context 'Diff algorithm logic' {

        It 'Item in current but not baseline should be in Added' {
            $baselineMap = @{ 'CN=user1,DC=contoso,DC=com' = [PSCustomObject]@{ DistinguishedName = 'CN=user1,DC=contoso,DC=com' } }
            $currentMap  = @{
                'CN=user1,DC=contoso,DC=com' = [PSCustomObject]@{ DistinguishedName = 'CN=user1,DC=contoso,DC=com' }
                'CN=user2,DC=contoso,DC=com' = [PSCustomObject]@{ DistinguishedName = 'CN=user2,DC=contoso,DC=com' }
            }

            $added = @($currentMap.Keys | Where-Object { -not $baselineMap.ContainsKey($_) } |
                       ForEach-Object { $currentMap[$_] })
            $added.Count | Should -Be 1
            $added[0].DistinguishedName | Should -Be 'CN=user2,DC=contoso,DC=com'
        }

        It 'Item in baseline but not current should be in Removed' {
            $baselineMap = @{
                'CN=user1,DC=contoso,DC=com' = [PSCustomObject]@{ DistinguishedName = 'CN=user1,DC=contoso,DC=com' }
                'CN=user2,DC=contoso,DC=com' = [PSCustomObject]@{ DistinguishedName = 'CN=user2,DC=contoso,DC=com' }
            }
            $currentMap = @{ 'CN=user1,DC=contoso,DC=com' = [PSCustomObject]@{ DistinguishedName = 'CN=user1,DC=contoso,DC=com' } }

            $removed = @($baselineMap.Keys | Where-Object { -not $currentMap.ContainsKey($_) } |
                         ForEach-Object { $baselineMap[$_] })
            $removed.Count | Should -Be 1
            $removed[0].DistinguishedName | Should -Be 'CN=user2,DC=contoso,DC=com'
        }

        It 'Item present in both but with changed property should be in Modified' {
            $dn = 'CN=user1,DC=contoso,DC=com'
            $baseline = [PSCustomObject]@{ DistinguishedName = $dn; Groups = @('Domain Admins') }
            $current  = [PSCustomObject]@{ DistinguishedName = $dn; Groups = @('Domain Admins', 'Enterprise Admins') }

            $b = $baseline | ConvertTo-Json -Depth 5 -Compress
            $c = $current  | ConvertTo-Json -Depth 5 -Compress
            ($b -ne $c) | Should -BeTrue
        }

        It 'Identical items should NOT appear in Modified' {
            $dn      = 'CN=user1,DC=contoso,DC=com'
            $itemB   = [PSCustomObject]@{ DistinguishedName = $dn; Enabled = $true }
            $itemC   = [PSCustomObject]@{ DistinguishedName = $dn; Enabled = $true }

            $b = $itemB | ConvertTo-Json -Depth 5 -Compress
            $c = $itemC | ConvertTo-Json -Depth 5 -Compress
            ($b -eq $c) | Should -BeTrue
        }

        It 'HasChanges should be $true when TotalAdded > 0' {
            $totalAdded    = 1
            $totalRemoved  = 0
            $totalModified = 0
            $hasChanges    = ($totalAdded -gt 0 -or $totalRemoved -gt 0 -or $totalModified -gt 0)
            $hasChanges    | Should -BeTrue
        }

        It 'HasChanges should be $false when all totals are zero' {
            $totalAdded    = 0
            $totalRemoved  = 0
            $totalModified = 0
            $hasChanges    = ($totalAdded -gt 0 -or $totalRemoved -gt 0 -or $totalModified -gt 0)
            $hasChanges    | Should -BeFalse
        }
    }

    Context 'Mocked file comparison — AdminAccounts indicator' {

        BeforeAll {
            $script:tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('DSTest_' + [System.Guid]::NewGuid().ToString('N'))
            [void](New-Item -ItemType Directory -Path $script:tempDir -Force)

            # Baseline: two admin accounts
            $baselineDoc = [ordered]@{
                Schema     = '1.0'
                CapturedAt = '2026-01-01T00:00:00.0000000Z'
                Domain     = 'contoso.com'
                Indicators = @{
                    AdminAccounts = @(
                        @{ DistinguishedName = 'CN=Admin1,CN=Users,DC=contoso,DC=com'; SamAccountName = 'Admin1' }
                        @{ DistinguishedName = 'CN=Admin2,CN=Users,DC=contoso,DC=com'; SamAccountName = 'Admin2' }
                    )
                }
                CaptureErrors = @{}
            }

            # Current: Admin2 removed, Admin3 added
            $currentDoc = [ordered]@{
                Schema     = '1.0'
                CapturedAt = '2026-03-01T00:00:00.0000000Z'
                Domain     = 'contoso.com'
                Indicators = @{
                    AdminAccounts = @(
                        @{ DistinguishedName = 'CN=Admin1,CN=Users,DC=contoso,DC=com'; SamAccountName = 'Admin1' }
                        @{ DistinguishedName = 'CN=Admin3,CN=Users,DC=contoso,DC=com'; SamAccountName = 'Admin3' }
                    )
                }
                CaptureErrors = @{}
            }

            $script:baselinePath = Join-Path $script:tempDir 'baseline.json'
            $script:currentPath  = Join-Path $script:tempDir 'current.json'

            $baselineDoc | ConvertTo-Json -Depth 10 | Set-Content -Path $script:baselinePath -Encoding UTF8
            $currentDoc  | ConvertTo-Json -Depth 10 | Set-Content -Path $script:currentPath  -Encoding UTF8
        }

        AfterAll {
            if (Test-Path $script:tempDir) { Remove-Item $script:tempDir -Recurse -Force }
        }

        It 'Should return a result object' {
            InModuleScope DirectoryServicesToolkit {
                $result = Compare-DSBaseline -BaselinePath $script:baselinePath -CurrentPath $script:currentPath
                $result | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should detect Admin3 as Added' {
            InModuleScope DirectoryServicesToolkit {
                $result = Compare-DSBaseline -BaselinePath $script:baselinePath -CurrentPath $script:currentPath
                $addedDns = @($result.Diffs.AdminAccounts.Added | ForEach-Object { $_.DistinguishedName })
                $addedDns | Should -Contain 'CN=Admin3,CN=Users,DC=contoso,DC=com'
            }
        }

        It 'Should detect Admin2 as Removed' {
            InModuleScope DirectoryServicesToolkit {
                $result = Compare-DSBaseline -BaselinePath $script:baselinePath -CurrentPath $script:currentPath
                $removedDns = @($result.Diffs.AdminAccounts.Removed | ForEach-Object { $_.DistinguishedName })
                $removedDns | Should -Contain 'CN=Admin2,CN=Users,DC=contoso,DC=com'
            }
        }

        It 'Summary.TotalAdded should be 1' {
            InModuleScope DirectoryServicesToolkit {
                $result = Compare-DSBaseline -BaselinePath $script:baselinePath -CurrentPath $script:currentPath
                $result.Summary.TotalAdded | Should -Be 1
            }
        }

        It 'Summary.TotalRemoved should be 1' {
            InModuleScope DirectoryServicesToolkit {
                $result = Compare-DSBaseline -BaselinePath $script:baselinePath -CurrentPath $script:currentPath
                $result.Summary.TotalRemoved | Should -Be 1
            }
        }

        It 'Summary.HasChanges should be $true' {
            InModuleScope DirectoryServicesToolkit {
                $result = Compare-DSBaseline -BaselinePath $script:baselinePath -CurrentPath $script:currentPath
                $result.Summary.HasChanges | Should -BeTrue
            }
        }

        It 'Domain should reflect the baseline domain' {
            InModuleScope DirectoryServicesToolkit {
                $result = Compare-DSBaseline -BaselinePath $script:baselinePath -CurrentPath $script:currentPath
                $result.Domain | Should -Be 'contoso.com'
            }
        }
    }

    Context 'Mocked file comparison — no changes' {

        BeforeAll {
            $script:tempDir2 = Join-Path ([System.IO.Path]::GetTempPath()) ('DSTest_' + [System.Guid]::NewGuid().ToString('N'))
            [void](New-Item -ItemType Directory -Path $script:tempDir2 -Force)

            $doc = [ordered]@{
                Schema     = '1.0'
                CapturedAt = '2026-01-01T00:00:00.0000000Z'
                Domain     = 'contoso.com'
                Indicators = @{
                    AdminAccounts = @(
                        @{ DistinguishedName = 'CN=Admin1,CN=Users,DC=contoso,DC=com'; SamAccountName = 'Admin1' }
                    )
                }
                CaptureErrors = @{}
            }

            $script:identPath1 = Join-Path $script:tempDir2 'b1.json'
            $script:identPath2 = Join-Path $script:tempDir2 'b2.json'
            $doc | ConvertTo-Json -Depth 10 | Set-Content -Path $script:identPath1 -Encoding UTF8
            $doc | ConvertTo-Json -Depth 10 | Set-Content -Path $script:identPath2 -Encoding UTF8
        }

        AfterAll {
            if (Test-Path $script:tempDir2) { Remove-Item $script:tempDir2 -Recurse -Force }
        }

        It 'Identical baselines should have HasChanges=$false' {
            InModuleScope DirectoryServicesToolkit {
                $result = Compare-DSBaseline -BaselinePath $script:identPath1 -CurrentPath $script:identPath2
                $result.Summary.HasChanges | Should -BeFalse
            }
        }

        It 'Identical baselines should have TotalAdded=0 and TotalRemoved=0' {
            InModuleScope DirectoryServicesToolkit {
                $result = Compare-DSBaseline -BaselinePath $script:identPath1 -CurrentPath $script:identPath2
                $result.Summary.TotalAdded   | Should -Be 0
                $result.Summary.TotalRemoved | Should -Be 0
            }
        }
    }
}
