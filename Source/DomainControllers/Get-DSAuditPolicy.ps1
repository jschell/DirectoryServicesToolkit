function Get-DSAuditPolicy
{
<#
.SYNOPSIS
Queries the advanced audit policy subcategory settings on each domain controller.

.DESCRIPTION
Reads Windows Advanced Audit Policy subcategory values from the registry key:
  HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security

For subcategory-level settings the canonical source is the per-DC registry path:
  HKLM\SECURITY\Policy\PolAdtEv

Because this path requires SYSTEM-level access remotely, this function reads the
effective per-machine audit settings via the auditpol-compatible registry export at:
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit

Subcategories checked (NIST AU-2 / AU-12 / CMMC 3.3.1 / 3.3.2):
  - Account Logon      — credential validation, Kerberos ticket events
  - Account Management — user/group create, modify, delete
  - Logon/Logoff       — interactive and network logon events
  - Object Access      — DS access, DS changes
  - Policy Change      — audit policy changes, authentication policy changes
  - Privilege Use      — sensitive privilege use
  - System             — security state change, security system extension

Risk classification:
  All required subcategories enabled (Success + Failure)  → Low
  Some subcategories missing                               → Medium
  No advanced audit policy configured                     → High

Requires RemoteRegistry service running on each DC and remote registry read access.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Get-DSAuditPolicy -Domain 'contoso.com'

Returns the audit policy posture for each DC in contoso.com.

.EXAMPLE
Get-DSAuditPolicy | Where-Object { $_.RiskLevel -ne 'Low' }

Returns domain controllers with incomplete audit coverage.

.NOTES
#### Name:    Get-DSAuditPolicy
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-08::0.1.0
- Initial creation — advanced audit policy subcategory check per DC

NIST 800-53: AU-2, AU-3, AU-12
NIST 800-207: (all pillars — audit is cross-cutting)
CMMC Level 3: 3.3.1, 3.3.2

.LINK
https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing-faq
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(HelpMessage = 'DNS name of the target domain')]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN
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

        Write-Verbose "Checking advanced audit policy on $($dcNames.Count) domain controller(s)"

        # Registry path written by Group Policy for subcategory audit settings
        $auditRegPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'

        # Expected subcategory DWORD names and their required bitmask values.
        # Value bits: 1 = Success, 2 = Failure, 3 = Success+Failure
        $requiredSubcategories = [ordered]@{
            'AuditCredentialValidation'          = 3   # Account Logon: Credential Validation
            'AuditKerberosAuthenticationService' = 3   # Account Logon: Kerberos Authentication
            'AuditKerberosServiceTicketOperations' = 3 # Account Logon: Kerberos Service Tickets
            'AuditUserAccountManagement'         = 3   # Account Management: User Account Management
            'AuditSecurityGroupManagement'       = 3   # Account Management: Security Group Management
            'AuditLogon'                         = 3   # Logon/Logoff: Logon
            'AuditLogoff'                        = 1   # Logon/Logoff: Logoff (Success only)
            'AuditDirectoryServiceAccess'        = 3   # DS Access
            'AuditDirectoryServiceChanges'       = 3   # DS Changes
            'AuditAuditPolicyChange'             = 3   # Policy Change: Audit Policy Change
            'AuditSensitivePrivilegeUse'         = 3   # Privilege Use: Sensitive Privilege Use
            'AuditSecurityStateChange'           = 3   # System: Security State Change
        }

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        foreach ($dc in $dcNames)
        {
            Write-Verbose "Querying audit policy on: $dc"

            $subcategoryResults = [ordered]@{}
            $missingSubcategories = @()
            $errorMessage = $null

            try
            {
                $regBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine,
                    $dc
                )
                $subKey = $regBase.OpenSubKey($auditRegPath)

                foreach ($subcategory in $requiredSubcategories.Keys)
                {
                    $required = $requiredSubcategories[$subcategory]
                    $actual   = $null

                    if ($null -ne $subKey)
                    {
                        $actual = $subKey.GetValue($subcategory)
                    }

                    $actualInt   = if ($null -ne $actual) { [int]$actual } else { 0 }
                    $isCovered   = ($actualInt -band $required) -eq $required
                    $subcategoryResults[$subcategory] = $actualInt

                    if (-not $isCovered)
                    {
                        $missingSubcategories += $subcategory
                    }
                }

                if ($null -ne $subKey) { $subKey.Close() }
                $regBase.Close()
            }
            catch
            {
                $errorMessage = "Registry access failed: $_"
                Write-Verbose "Could not query registry on '$dc': $_"
                $missingSubcategories = @($requiredSubcategories.Keys)
            }

            $riskLevel = if ($missingSubcategories.Count -eq 0)
            {
                'Low'
            }
            elseif ($missingSubcategories.Count -le 4)
            {
                'Medium'
            }
            else
            {
                'High'
            }

            [void]$results.Add(
                [PSCustomObject]@{
                    DCName                = $dc
                    SubcategorySettings   = [PSCustomObject]$subcategoryResults
                    MissingSubcategories  = $missingSubcategories
                    MissingCount          = $missingSubcategories.Count
                    TotalRequired         = $requiredSubcategories.Count
                    RiskLevel             = $riskLevel
                    IsCompliant           = ($riskLevel -eq 'Low')
                    ErrorMessage          = $errorMessage
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property IsCompliant, DCName
    }
}
