# DirectoryServicesToolkit.psm1
# Root module file — dot-sources all public functions at import time.
# This file is used during development (Import-Module ./Source/DirectoryServicesToolkit.psm1).
# The build process generates a compiled version in Output/.

$publicFolders = @(
    'Enumeration'
    'Security'
    'AccountHygiene'
    'Trusts'
    'DomainControllers'
    'DNS'
    'Reporting'
    'Utilities'
)

foreach ($folder in $publicFolders)
{
    $folderPath = Join-Path $PSScriptRoot $folder
    if (Test-Path $folderPath)
    {
        Get-ChildItem -Path $folderPath -Filter '*.ps1' | ForEach-Object {
            . $_.FullName
        }
    }
}

# Private helpers — loaded but not exported
$privatePath = Join-Path $PSScriptRoot 'Private'
if (Test-Path $privatePath)
{
    Get-ChildItem -Path $privatePath -Filter '*.ps1' | ForEach-Object {
        . $_.FullName
    }
}
