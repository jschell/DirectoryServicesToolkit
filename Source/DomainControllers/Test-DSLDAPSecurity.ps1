function Test-DSLDAPSecurity
{
<#
.SYNOPSIS
Runs both LDAP signing and channel binding checks and returns a combined per-DC assessment.

.DESCRIPTION
Calls Test-DSLDAPSigning and Test-DSLDAPChannelBinding for each domain controller and
merges the results into a unified per-DC record. A domain controller is fully compliant
only when both LDAP signing (value 2) and channel binding (value 2) are enforced. Also
outputs a domain-level summary via Write-Verbose. Requires the RemoteRegistry service on
each DC and an account with remote registry read rights.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Test-DSLDAPSecurity -Domain 'contoso.com'

Returns a combined LDAP security assessment for each DC in contoso.com.

.EXAMPLE
Test-DSLDAPSecurity -Domain 'contoso.com' | Where-Object { -not $_.IsFullyCompliant }

Returns only DCs that fail on either signing or channel binding.

.NOTES
#### Name:    Test-DSLDAPSecurity
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
        Write-Verbose "Running combined LDAP security assessment for domain: $Domain"
        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $signingResults     = Test-DSLDAPSigning -Domain $Domain
        $channelBindResults = Test-DSLDAPChannelBinding -Domain $Domain

        # Index channel binding results by DCName for O(1) join
        $cbIndex = @{}
        foreach ($cb in $channelBindResults)
        {
            $cbIndex[$cb.DCName] = $cb
        }

        foreach ($sig in $signingResults)
        {
            $cb = $cbIndex[$sig.DCName]

            $cbValue     = if ($null -ne $cb) { $cb.ChannelBindingValue } else { $null }
            $cbRisk      = if ($null -ne $cb) { $cb.RiskLevel } else { 'Unknown' }
            $cbCompliant = if ($null -ne $cb) { $cb.IsCompliant } else { $false }

            $fullyCompliant = $sig.IsCompliant -and $cbCompliant

            $compositeRisk = if ($sig.RiskLevel -eq 'Critical' -or $cbRisk -eq 'Critical') { 'Critical' }
                             elseif ($sig.RiskLevel -eq 'Medium' -or $cbRisk -eq 'Medium') { 'Medium' }
                             elseif ($fullyCompliant) { 'Low' }
                             else { 'Unknown' }

            [void]$results.Add(
                [PSCustomObject]@{
                    DCName                 = $sig.DCName
                    SigningValue           = $sig.SigningValue
                    SigningRiskLevel       = $sig.RiskLevel
                    ChannelBindingValue    = $cbValue
                    ChannelBindingRisk     = $cbRisk
                    IsSigningCompliant     = $sig.IsCompliant
                    IsChannelBindCompliant = $cbCompliant
                    IsFullyCompliant       = $fullyCompliant
                    CompositeRiskLevel     = $compositeRisk
                }
            )
        }
    }

    End
    {
        $total     = $results.Count
        $compliant = ($results | Where-Object { $_.IsFullyCompliant }).Count

        Write-Verbose "LDAP Security Summary: $compliant / $total DCs fully compliant (signing + channel binding)"

        $results | Sort-Object -Property IsFullyCompliant, DCName
    }
}
