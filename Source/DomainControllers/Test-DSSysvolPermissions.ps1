function Test-DSSysvolPermissions
{
<#
.SYNOPSIS
Checks NTFS ACLs on the SYSVOL and NETLOGON shares for non-privileged write access.

.DESCRIPTION
Reads the NTFS security descriptor of the SYSVOL and NETLOGON UNC paths for each
domain controller and identifies non-privileged principals with write-equivalent rights.

Write access to SYSVOL or NETLOGON is critical: an attacker can plant malicious scripts,
replace legitimate logon scripts, or modify GPO files directly on disk — bypassing the
Group Policy LDAP protections checked by Find-DSGPOPermissions.

Dangerous NTFS rights checked:
  - FullControl    — complete access
  - Modify         — modify files, sub-directories
  - Write          — write files
  - WriteData      — write file contents
  - WriteAttributes — write file attributes
  - CreateFiles    — create new files
  - CreateDirectories — create subdirectories

Expected privileged principals (excluded by default):
  - BUILTIN\Administrators, CREATOR OWNER, NT AUTHORITY\SYSTEM
  - BUILTIN\Server Operators, Domain Admins, Enterprise Admins
  - Authenticated Users (Read-only access — filtered by right type)

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeSafeAces
When specified, returns all ACEs including those held by expected privileged principals.

.EXAMPLE
Test-DSSysvolPermissions -Domain 'contoso.com'

Returns non-privileged write ACEs on SYSVOL and NETLOGON for each DC.

.EXAMPLE
Test-DSSysvolPermissions | Where-Object { $_.IsVulnerable }

Returns only entries representing a SYSVOL write access risk.

.NOTES
#### Name:    Test-DSSysvolPermissions
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-08::0.1.0
- Initial creation — SYSVOL/NETLOGON NTFS permission check per DC

NIST 800-53: CM-6, SI-7, AC-3, AC-6
NIST 800-207: Policy Engine pillar — integrity of policy distribution infrastructure
CMMC Level 3: 3.4.2 (establish baseline configurations), 3.3.8 (protect audit info)

.LINK
https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/sysvol-dfs-replication-default-permissions
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(HelpMessage = 'DNS name of the target domain')]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter(HelpMessage = 'Include ACEs held by expected privileged principals')]
        [switch]$IncludeSafeAces
    )

    Begin
    {
        try
        {
            $dcNames = Get-DSDomainControllerNames -Domain $Domain
        }
        catch
        {
            Write-Error "Cannot enumerate domain controllers for '$Domain': $_"
            return
        }

        Write-Verbose "Checking SYSVOL/NETLOGON permissions on $($dcNames.Count) domain controller(s)"

        $dangerousRights = @(
            'FullControl'
            'Modify'
            [System.Security.AccessControl.FileSystemRights]::Write
            [System.Security.AccessControl.FileSystemRights]::WriteData
            [System.Security.AccessControl.FileSystemRights]::CreateFiles
            [System.Security.AccessControl.FileSystemRights]::CreateDirectories
        )

        $safeIdentityPatterns = @(
            'Administrators'
            'Domain Admins'
            'Enterprise Admins'
            'SYSTEM'
            'CREATOR OWNER'
            'Server Operators'
            'NT AUTHORITY\SYSTEM'
            'BUILTIN\Administrators'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        foreach ($dc in $dcNames)
        {
            $sharePaths = @(
                @{ Share = 'SYSVOL';   UNC = "\\$dc\SYSVOL" }
                @{ Share = 'NETLOGON'; UNC = "\\$dc\NETLOGON" }
            )

            foreach ($shareInfo in $sharePaths)
            {
                $shareName = $shareInfo.Share
                $uncPath   = $shareInfo.UNC

                Write-Verbose "Reading ACL for $shareName on $dc ($uncPath)"

                try
                {
                    $acl = Get-Acl -Path $uncPath -ErrorAction Stop
                }
                catch
                {
                    [void]$results.Add(
                        [PSCustomObject]@{
                            DCName            = $dc
                            ShareName         = $shareName
                            UNCPath           = $uncPath
                            IdentityReference = $null
                            Rights            = $null
                            IsInherited       = $null
                            IsPrivilegedOwner = $null
                            IsVulnerable      = $false
                            RiskLevel         = 'Unknown'
                            Finding           = $null
                            ErrorMessage      = "ACL read failed: $_"
                        }
                    )
                    continue
                }

                foreach ($ace in $acl.Access)
                {
                    if ($ace.AccessControlType -ne 'Allow') { continue }

                    $rights   = $ace.FileSystemRights.ToString()
                    $identity = $ace.IdentityReference.Value

                    $hasDangerousRight = $false
                    $matchedRights     = @()

                    foreach ($right in @('FullControl', 'Modify', 'Write', 'WriteData', 'CreateFiles', 'CreateDirectories', 'WriteAttributes'))
                    {
                        if ($rights -match $right)
                        {
                            $hasDangerousRight = $true
                            $matchedRights    += $right
                        }
                    }

                    if (-not $hasDangerousRight) { continue }

                    $isSafe = $false
                    foreach ($pattern in $safeIdentityPatterns)
                    {
                        if ($identity -like "*$pattern*") { $isSafe = $true; break }
                    }

                    if ($isSafe -and -not $IncludeSafeAces) { continue }

                    $isVulnerable = -not $isSafe

                    $riskLevel = if ($isVulnerable)
                    {
                        if ($matchedRights -contains 'FullControl') { 'Critical' } else { 'High' }
                    }
                    else
                    {
                        'Informational'
                    }

                    [void]$results.Add(
                        [PSCustomObject]@{
                            DCName            = $dc
                            ShareName         = $shareName
                            UNCPath           = $uncPath
                            IdentityReference = $identity
                            Rights            = $rights
                            MatchedRights     = $matchedRights
                            IsInherited       = $ace.IsInherited
                            IsPrivilegedOwner = $isSafe
                            IsVulnerable      = $isVulnerable
                            RiskLevel         = $riskLevel
                            Finding           = if ($isVulnerable) { "SYSVOL write: '$identity' has $($matchedRights -join ', ') on \\$dc\$shareName" } else { $null }
                            ErrorMessage      = $null
                        }
                    )
                }
            }
        }
    }

    End
    {
        $results | Sort-Object -Property IsVulnerable -Descending
    }
}
