function Find-StaleDNSDomainRecord
{
<#
.SYNOPSIS
Detects stale A and AAAA records in AD-integrated DNS zones.

.DESCRIPTION
Identifies DNS domain records (A and/or AAAA) pointing to offline or
decommissioned domain controllers. Compares current DNS entries for the
domain against the resolved addresses of known domain controllers and
flags any records that do not match an active DC address.

Handles partial IP match edge cases by requiring a whole-word match, so
addresses that share a prefix (e.g. x.x.x.1, x.x.x.11, x.x.x.12) are
evaluated correctly.

Requires connectivity to the PDC Emulator via ADWS (Active Directory
Web Services).

.PARAMETER Domain
The DNS name of the domain to check. Defaults to the current user's DNS domain.

.PARAMETER AddressType
The record type(s) to evaluate: A (IPv4), AAAA (IPv6), or All. Defaults to All.

.PARAMETER StaleRecordsOnly
When specified, returns only the IP addresses of stale records rather than
the full result objects.

.EXAMPLE
Find-StaleDNSDomainRecord -Domain 'contoso.com'

Returns all DNS domain records with their associated DC name, flagging stale
entries with '!--STALE ENTRY--!'.

.EXAMPLE
Find-StaleDNSDomainRecord -Domain 'contoso.com' -StaleRecordsOnly

Returns only the IP addresses that do not resolve to an active DC.

.NOTES
#### Name:    Find-StaleDNSDomainRecord
#### Author:  J Schell
#### Version: 0.1.1
#### License: MIT License

Changelog:
2017-05-01::0.1.1
- Fixed logic: check DC addr vs trying to resolve reverse entry
- Match whole word, not partial, to avoid false matches on shared prefixes
- Add try/catch for domain lookup in Begin
- Changed stale entry value to var set in Begin

2017-04-28::0.1.0
- Initial creation

.LINK
https://gist.github.com/jschell/6e469dc5237408172af6faf73b227ac8
#>


    [CmdletBinding()]
    Param
    (

        $Domain = $env:UserDNSDomain,

        [ValidateSet('A','AAAA','All')]
        $AddressType = 'All',

        [Switch]
        $StaleRecordsOnly
    )

    Begin
    {
        $staleRecordString = '!--STALE ENTRY--!'
        Try
        {
            $targetPDC = (Get-ADDomain -Server $Domain).pdcEmulator
        }
        Catch
        {
            Write-Error $_
            Break;
        }

        $domainControllerHostnames = @(Get-ADDomainController -Filter * -Server $Domain |
            Select-Object -ExpandProperty Hostname | Sort-Object )

        $currentEntries = Resolve-DnsName -Name $Domain -Server $targetPDC

        $current_v4 = $currentEntries | Where-Object {$_.Type -eq 'A'} |
            Select-Object -ExpandProperty IpAddress
        $current_v6 = $currentEntries | Where-Object {$_.Type -eq 'AAAA'} |
            Select-Object -ExpandProperty IpAddress
        $resolvedAddress = @()

        $currentDomainControllerAddr = @()
        foreach( $dc in $domainControllerHostnames )
        {
            $dcAddr = Resolve-DnsName -Name $dc -Server $targetPDC -ErrorAction SilentlyContinue
            $dcV4 = ($dcAddr | Where-Object {$_.Type -eq 'A'}).IpAddress
            $dcV6 = ($dcAddr | Where-Object {$_.Type -eq 'AAAA'}).IpAddress
            $dcIpDetail = New-Object -TypeName PsObject -Property ([ordered]@{
                ComputerName = $dc
                IpAddress = @(
                                $dcV4
                                $dcV6
                            )
            })
            $currentDomainControllerAddr += @( $dcIpDetail )
        }
    }
    Process
    {
        Switch( $AddressType )
        {
            'A'     { $AddressList = @( $current_v4 ) }
            'AAAA'  { $AddressList = @( $current_v6 ) }
            'All'
            {
                $AddressList = @( $current_v4 )
                $AddressList += @( $current_v6 )
            }
        }

        foreach( $entry in $AddressList )
        {
            $queryResult = New-Object -TypeName PsObject -Property ([ordered]@{
                ComputerName = $null
                IpAddress = $entry
                RiskLevel = $null
            })

            if( $currentDomainControllerAddr.IpAddress -match $entry)
            {
                $queryResult.ComputerName = ($currentDomainControllerAddr |
                    Where-Object {$_.IpAddress -match "$($entry)\b" }).computername
                # RiskLevel: record maps to a known active DC — no immediate risk.
                $queryResult.RiskLevel = 'Informational'
            }
            else
            {
                $queryResult.ComputerName = $staleRecordString
                # RiskLevel: stale DC records can be hijacked by registering the orphaned IP,
                # enabling man-in-the-middle or authentication relay against domain clients.
                $queryResult.RiskLevel = 'Medium'
            }

            $resolvedAddress += @( $queryResult )
        }
    }
    End
    {
        $resolvedAddress = $resolvedAddress | Sort-Object -Property ComputerName
        if($StaleRecordsOnly)
        {
            $resolvedAddress = $resolvedAddress |
                Where-Object {$_.ComputerName -eq $staleRecordString} |
                Select-Object -ExpandProperty IpAddress
        }
        $resolvedAddress
    }
}
