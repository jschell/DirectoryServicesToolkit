function Get-DSMachineAccountQuota
{
<#
.SYNOPSIS
Checks the ms-DS-MachineAccountQuota value on the domain to assess computer join risk.

.DESCRIPTION
Reads the ms-DS-MachineAccountQuota attribute on the domain NC root, which controls how
many computer objects any authenticated user can add to the domain. The default value of
10 allows any domain user to create machine accounts, which is a prerequisite for
Resource-Based Constrained Delegation (RBCD) attacks and coercion-based escalation chains.
A value greater than zero is considered a risk. Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Get-DSMachineAccountQuota -Domain 'contoso.com'

Returns the MAQ value and risk assessment for contoso.com.

.EXAMPLE
Get-DSMachineAccountQuota -Domain 'contoso.com' | Where-Object { $_.MachineAccountQuota -gt 0 }

Returns only domains where non-admin machine account creation is permitted.

.NOTES
#### Name:    Get-DSMachineAccountQuota
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-04::0.1.0
- Initial creation
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
            $DomainName = Resolve-DSDomainName -Domain $Domain
        }
        catch
        {
            Write-Error "Cannot connect to domain '$Domain': $_"
            return
        }

        Write-Verbose "Checking machine account quota for domain: $DomainName"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $ldapPath = "LDAP://$domainDN"

        $ldapFilter = '(objectClass=domain)'
        $properties = @('distinguishedName', 'ms-DS-MachineAccountQuota', 'name')
    }

    Process
    {
        $queryResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($obj in $queryResults)
        {
            $maq = if ($null -ne $obj['ms-ds-machineaccountquota'] -and $obj['ms-ds-machineaccountquota'].Count -gt 0) { [int]$obj['ms-ds-machineaccountquota'][0] } else { 10 }

            $riskLevel = if ($maq -eq 0) { 'Low' }
                         elseif ($maq -le 5) { 'Medium' }
                         else { 'High' }

            $finding = if ($maq -eq 0) { 'Machine account quota is 0 — only admins can join computers to the domain' }
                       elseif ($maq -gt 0) { "Any authenticated user can create up to $maq computer accounts — RBCD and coercion attack surface exposed" }
                       else { $null }

            [PSCustomObject]@{
                DomainName           = $DomainName
                DomainDN             = [string]$obj['distinguishedname'][0]
                MachineAccountQuota  = $maq
                RiskLevel            = $riskLevel
                Finding              = $finding
                Remediation          = if ($maq -gt 0) { "Set ms-DS-MachineAccountQuota to 0 on the domain NC root to prevent non-admin computer account creation" } else { $null }
            }
        }
    }

    End
    {
    }
}
