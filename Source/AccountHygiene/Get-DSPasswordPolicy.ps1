function Get-DSPasswordPolicy
{
<#
.SYNOPSIS
Returns the Default Domain Password Policy and all Fine-Grained Password Policies.

.DESCRIPTION
Retrieves the domain password policy and any Fine-Grained Password Policies (PSOs)
configured in the domain. For each PSO, includes:

  - Minimum password length
  - Password history count
  - Maximum and minimum password age
  - Lockout threshold and observation window
  - Complexity requirements
  - Reversible encryption flag
  - Precedence value
  - Applied-to groups or accounts (msDS-PSOAppliesTo)

The Default Domain Policy is read from the domain root DirectoryEntry object.
PSOs are read from CN=Password Settings Container,CN=System,<DomainDN>.

Interval attributes (maxPwdAge, lockoutDuration, etc.) are stored as negative
100-nanosecond intervals in Active Directory; this function converts them to
[TimeSpan] objects. A value of 0 in the store means "no limit" and is returned
as [TimeSpan]::MaxValue.

Requires read access to the Password Settings Container
(CN=Password Settings Container,CN=System,DC=...).

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER IncludeFineGrained
When specified, Fine-Grained Password Policies are included in results
alongside the Default Domain Policy. Defaults to $true.

.EXAMPLE
Get-DSPasswordPolicy -Domain 'contoso.com'

Returns the Default Domain Password Policy and all PSOs in contoso.com.

.EXAMPLE
Get-DSPasswordPolicy -IncludeFineGrained:$false

Returns only the Default Domain Password Policy.

.NOTES
#### Name:    Get-DSPasswordPolicy
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2026-03-03::0.1.0
- Initial creation
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter()]
        [bool]$IncludeFineGrained = $true
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

        Write-Verbose "Querying domain: $DomainName for password policies"

        $domainDn = 'DC=' + ($DomainName -replace '\.', ',DC=')
    }

    Process
    {
        # ── Default Domain Policy ─────────────────────────────────────────────

        $domainRoot = $null
        try
        {
            $domainRoot = [adsi]"LDAP://$DomainName"

            $maxPwdAge   = ConvertFrom-ADInterval $domainRoot.Properties['maxPwdAge'][0]
            $minPwdAge   = ConvertFrom-ADInterval $domainRoot.Properties['minPwdAge'][0]
            $lockoutDur  = ConvertFrom-ADInterval $domainRoot.Properties['lockoutDuration'][0]
            $lockoutObs  = ConvertFrom-ADInterval $domainRoot.Properties['lockoutObservationWindow'][0]

            $pwdProps    = [int]$domainRoot.Properties['pwdProperties'][0]

            $pwdMinLen      = [int]$domainRoot.Properties['minPwdLength'][0]
            $pwdHistoryLen  = [int]$domainRoot.Properties['pwdHistoryLength'][0]
            $lockoutThresh  = [int]$domainRoot.Properties['lockoutThreshold'][0]
            $complexEnabled = [bool]($pwdProps -band 1)
            $reversibleEnc  = [bool]($pwdProps -band 16)

            # RiskLevel: reversible encryption stores passwords recoverable as plaintext — Critical.
            # No complexity + short minimum length (<8) = Critical. Any single weak attribute
            # (no complexity, length <8, history <12, no lockout) = High. Otherwise Low.
            $pwdPolicyRisk = if ($reversibleEnc) { 'Critical' }
                             elseif (-not $complexEnabled -and $pwdMinLen -lt 8) { 'Critical' }
                             elseif (-not $complexEnabled -or $pwdMinLen -lt 8 -or $pwdHistoryLen -lt 12 -or $lockoutThresh -eq 0) { 'High' }
                             else { 'Low' }

            [PSCustomObject]@{
                PolicyType               = 'Default'
                Name                     = 'Default Domain Policy'
                MinPasswordLength        = $pwdMinLen
                PasswordHistoryCount     = $pwdHistoryLen
                MaxPasswordAge           = $maxPwdAge
                MinPasswordAge           = $minPwdAge
                LockoutThreshold         = $lockoutThresh
                LockoutDuration          = $lockoutDur
                LockoutObservationWindow = $lockoutObs
                ComplexityEnabled        = $complexEnabled
                ReversibleEncryption     = $reversibleEnc
                Precedence               = $null
                AppliesTo                = $null
                RiskLevel                = $pwdPolicyRisk
            }
        }
        catch
        {
            Write-Error "Failed to read Default Domain Policy: $_"
        }
        finally
        {
            if ($null -ne $domainRoot) { $domainRoot.Dispose() }
        }

        # ── Fine-Grained Password Policies (PSOs) ─────────────────────────────

        if (-not $IncludeFineGrained) { return }

        $psoPath   = "LDAP://CN=Password Settings Container,CN=System,$domainDn"
        $psoFilter = '(objectClass=msDS-PasswordSettings)'
        $psoProps  = @(
            'name'
            'msDS-PasswordSettingsPrecedence'
            'msDS-MaximumPasswordAge'
            'msDS-MinimumPasswordAge'
            'msDS-MinimumPasswordLength'
            'msDS-PasswordHistoryLength'
            'msDS-LockoutThreshold'
            'msDS-LockoutDuration'
            'msDS-LockoutObservationWindow'
            'msDS-PasswordComplexityEnabled'
            'msDS-PasswordReversibleEncryptionEnabled'
            'msDS-PSOAppliesTo'
        )

        $psoResults = $null
        try
        {
            $psoResults = Invoke-DSDirectorySearch -LdapPath $psoPath `
                -Filter $psoFilter -Properties $psoProps
        }
        catch
        {
            Write-Verbose "Could not query PSO container (may not exist or insufficient rights): $_"
            return
        }

        Write-Verbose "Found $($psoResults.Count) Fine-Grained Password Policies"

        foreach ($pso in $psoResults)
        {
            $maxAge  = ConvertFrom-ADInterval $pso['msds-maximumpasswordage'][0]
            $minAge  = ConvertFrom-ADInterval $pso['msds-minimumpasswordage'][0]
            $lockDur = ConvertFrom-ADInterval $pso['msds-lockoutduration'][0]
            $lockObs = ConvertFrom-ADInterval $pso['msds-lockoutobservationwindow'][0]

            $complexRaw   = $pso['msds-passwordcomplexityenabled']
            $revEncRaw    = $pso['msds-passwordreversibleencryptionenabled']
            $appliesToRaw = $pso['msds-psoapplies to']
            if (-not $appliesToRaw) { $appliesToRaw = $pso['msds-psoapplies_to'] }
            if (-not $appliesToRaw) { $appliesToRaw = $pso['msds-psoapplies'] }

            # Try the key with space as ADSI returns it
            $appliesToKey = ($pso.Keys | Where-Object { $_ -like 'msds-psoapplies*' } | Select-Object -First 1)
            $appliesToRaw = if ($appliesToKey) { $pso[$appliesToKey] } else { @() }

            $psoMinLen       = [int]$pso['msds-minimumpasswordlength'][0]
            $psoHistoryLen   = [int]$pso['msds-passwordhistorylength'][0]
            $psoLockout      = [int]$pso['msds-lockoutthreshold'][0]
            $psoComplex      = if ($complexRaw -and $complexRaw.Count -gt 0) { [bool]$complexRaw[0] } else { $false }
            $psoRevEnc       = if ($revEncRaw -and $revEncRaw.Count -gt 0) { [bool]$revEncRaw[0] } else { $false }

            # RiskLevel: same criteria as Default Domain Policy applied to PSO settings.
            $psoPolicyRisk = if ($psoRevEnc) { 'Critical' }
                             elseif (-not $psoComplex -and $psoMinLen -lt 8) { 'Critical' }
                             elseif (-not $psoComplex -or $psoMinLen -lt 8 -or $psoHistoryLen -lt 12 -or $psoLockout -eq 0) { 'High' }
                             else { 'Low' }

            [PSCustomObject]@{
                PolicyType               = 'FineGrained'
                Name                     = [string]$pso['name'][0]
                MinPasswordLength        = $psoMinLen
                PasswordHistoryCount     = $psoHistoryLen
                MaxPasswordAge           = $maxAge
                MinPasswordAge           = $minAge
                LockoutThreshold         = $psoLockout
                LockoutDuration          = $lockDur
                LockoutObservationWindow = $lockObs
                ComplexityEnabled        = $psoComplex
                ReversibleEncryption     = $psoRevEnc
                Precedence               = [int]$pso['msds-passwordsettingsprecedence'][0]
                AppliesTo                = if ($appliesToRaw -and $appliesToRaw.Count -gt 0) { @($appliesToRaw) } else { @() }
                RiskLevel                = $psoPolicyRisk
            }
        }
    }

    End {}
}


function ConvertFrom-ADInterval
{
<#
.SYNOPSIS
Internal helper — converts an AD negative 100-nanosecond interval to a TimeSpan.
#>
    [CmdletBinding()]
    [OutputType([TimeSpan])]
    Param
    (
        [Parameter()]
        $Value
    )

    if ($null -eq $Value) { return [TimeSpan]::Zero }

    $ticks = 0
    if ($null -ne $Value -and $Value.GetType().Name -eq 'LargeInteger')
    {
        # COM LargeInteger from ADSI property bag
        $high  = $Value.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $null, $Value, $null)
        $low   = $Value.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $null, $Value, $null)
        $ticks = ([long]$high -shl 32) -bor ([long]([uint32]$low))
    }
    else
    {
        $ticks = [long]$Value
    }

    if ($ticks -eq 0) { return [TimeSpan]::MaxValue }

    [TimeSpan]::FromTicks([Math]::Abs($ticks))
}
