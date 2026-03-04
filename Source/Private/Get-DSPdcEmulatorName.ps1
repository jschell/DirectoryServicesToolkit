function Get-DSPdcEmulatorName
{
<#
.SYNOPSIS
Internal helper — returns the PDC Emulator hostname for a domain.

.NOTES
This private function wraps [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain()
so that callers can be mocked in unit tests without requiring a live domain connection.
#>
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory)]
        [string]$Domain
    )

    $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
    $DomainEntry   = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
    $Name          = $DomainEntry.PdcRoleOwner.Name
    $DomainEntry.Dispose()
    return $Name
}
