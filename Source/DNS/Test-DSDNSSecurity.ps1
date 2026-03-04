function Test-DSDNSSecurity
{
<#
.SYNOPSIS
Checks DNS zone security settings for common misconfigurations.

.DESCRIPTION
Evaluates AD-Integrated DNS zones for the following security settings:

  Dynamic Update Policy
    Secure (2)             — only authenticated domain members can register records
    NonsecureAndSecure (1) — any client, authenticated or not, can register
    None (0)               — no dynamic updates permitted

  Zone Transfer Permissions
    Whether zone transfers are permitted, and if so, to which targets:
    NoTransfer (3)  — transfers disabled
    ToNsServers (1) — transfers limited to NS-listed servers
    ToList (2)      — transfers limited to an explicit IP list
    ToAny (0)       — transfers allowed to any server (high risk)

Queries the MicrosoftDNS_Zone WMI class on the domain PDC Emulator from the
root\MicrosoftDNS namespace. Requires WMI/CIM access to the PDC Emulator.

Skips autocreated zones, reverse lookup zones, and cache zones (ZoneType=0)
as these are not relevant to the security evaluation.

Requires read access to the domain and CIM/WMI connectivity to the PDC Emulator.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.PARAMETER Zone
A specific DNS zone to evaluate. If omitted, all zones are evaluated.

.EXAMPLE
Test-DSDNSSecurity -Domain 'contoso.com'

Returns security configuration for all DNS zones in contoso.com.

.EXAMPLE
Test-DSDNSSecurity -Zone 'contoso.com'

Returns security configuration for the contoso.com zone only.

.NOTES
#### Name:    Test-DSDNSSecurity
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
        [string]$Zone
    )

    Begin
    {
        try
        {
            $DomainName  = Resolve-DSDomainName -Domain $Domain
            $PdcEmulator = Get-DSPdcEmulatorName -Domain $Domain
        }
        catch
        {
            Write-Error "Cannot connect to domain '$Domain': $_"
            return
        }

        Write-Verbose "Querying DNS zone security in domain '$DomainName' via PDC Emulator: $PdcEmulator"

        # ZoneType integer → human-readable name
        $zoneTypeMap = @{
            0 = 'Cache'
            1 = 'Primary'
            2 = 'Secondary'
            3 = 'Stub'
            4 = 'Forwarder'
        }

        # DynamicUpdate integer → human-readable name
        $dynamicUpdateMap = @{
            0 = 'None'
            1 = 'NonsecureAndSecure'
            2 = 'Secure'
        }

        # SecureSecondaries integer → human-readable policy name
        $transferPolicyMap = @{
            0 = 'ToAny'
            1 = 'ToNsServers'
            2 = 'ToList'
            3 = 'NoTransfer'
        }
    }

    Process
    {
        $cimSession = $null
        $allZones   = $null

        try
        {
            $cimSession = New-CimSession -ComputerName $PdcEmulator -ErrorAction Stop
            $allZones   = Get-CimInstance -CimSession $cimSession `
                -Namespace 'root\MicrosoftDNS' `
                -ClassName 'MicrosoftDNS_Zone' `
                -ErrorAction Stop
        }
        catch
        {
            Write-Error "Failed to query DNS zones via WMI on '$PdcEmulator': $_"
            return
        }
        finally
        {
            if ($null -ne $cimSession) { Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue }
        }

        Write-Verbose "Retrieved $($allZones.Count) zones from WMI"

        foreach ($wmiZone in $allZones)
        {
            # Skip criteria
            if ($wmiZone.IsAutoCreated)        { continue }
            if ($wmiZone.IsReverseLookupZone)  { continue }
            if ($wmiZone.ZoneType -eq 0)       { continue }   # cache zone

            $zoneName = $wmiZone.Name

            # Apply -Zone filter if specified
            if ($Zone -and $zoneName -ne $Zone) { continue }

            $zoneTypeInt      = [int]$wmiZone.ZoneType
            $dynamicUpdateInt = [int]$wmiZone.DynamicUpdate
            $secSecInt        = [int]$wmiZone.SecureSecondaries

            $zoneTypeName      = if ($zoneTypeMap.ContainsKey($zoneTypeInt)) { $zoneTypeMap[$zoneTypeInt] } else { "Unknown($zoneTypeInt)" }
            $dynamicUpdateName = if ($dynamicUpdateMap.ContainsKey($dynamicUpdateInt)) { $dynamicUpdateMap[$dynamicUpdateInt] } else { "Unknown($dynamicUpdateInt)" }
            $transferPolicy    = if ($transferPolicyMap.ContainsKey($secSecInt)) { $transferPolicyMap[$secSecInt] } else { "Unknown($secSecInt)" }

            # ── Security evaluation ───────────────────────────────────────────

            $unsecureDynamic   = ($dynamicUpdateInt -eq 1)
            $transfersEnabled  = ($secSecInt -ne 3)
            $transferToAny     = ($secSecInt -eq 0)

            $riskFactors = [System.Collections.Generic.List[string]]::new()
            if ($unsecureDynamic) { [void]$riskFactors.Add('UnsecuredDynamicUpdate') }
            if ($transferToAny)   { [void]$riskFactors.Add('ZoneTransferToAnyServer') }
            elseif ($transfersEnabled) { [void]$riskFactors.Add('ZoneTransferEnabled') }

            $transferTargets = $null
            if ($transfersEnabled -and $null -ne $wmiZone.SecondaryServers)
            {
                $transferTargets = @($wmiZone.SecondaryServers)
            }

            [PSCustomObject]@{
                ZoneName               = $zoneName
                ZoneType               = $zoneTypeName
                DynamicUpdate          = $dynamicUpdateName
                AllowsUnsecuredDynamic = $unsecureDynamic
                ZoneTransferEnabled    = $transfersEnabled
                ZoneTransferPolicy     = $transferPolicy
                ZoneTransferTargets    = $transferTargets
                RiskFactors            = @($riskFactors)
                IsReverseLookupZone    = [bool]$wmiZone.IsReverseLookupZone
            }
        }
    }

    End {}
}
