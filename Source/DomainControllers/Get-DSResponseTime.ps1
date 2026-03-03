function Get-DSResponseTime
{
<#
.SYNOPSIS
Measures LDAP and Global Catalog response latency across Domain Controllers.

.DESCRIPTION
Quick tool to view response delays on Domain Controllers. Tests connectivity
on LDAP (port 389) and Global Catalog (port 3268) ports and returns response
times in milliseconds. Useful for diagnosing slow DC identification.

.PARAMETER TargetDomain
The DNS name of the domain to query. Defaults to the current user's DNS domain.

.PARAMETER Forest
When specified, measures response times across all domains in the forest.

.EXAMPLE
Get-DSResponseTime

Returns LDAP and GC response times for all DCs in the current domain.

.EXAMPLE
Get-DSResponseTime -TargetDomain 'contoso.com' -Forest

Returns response times for all DCs across all domains in the contoso.com forest.

.NOTES
#### Name:    Get-DSResponseTime
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2017-01-25::0.1.0
- Initial creation

.LINK
https://gist.github.com/jschell/f34321ec9c73e89b52c90c899bf680c4
#>


    [CmdletBinding()]
    [OutputType([PSObject])]
    Param
    (
        [Parameter( Mandatory = $False )]
        [String]
        $TargetDomain = $env:USERDNSDOMAIN,

        [Parameter( Mandatory = $False )]
        [Switch]
        $Forest
    )

    Begin
    {
        $DomainContext = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::New("Domain", $TargetDomain)

        if($Forest)
        {
            $DomainEntry = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $DomainListAsString = @( $DomainEntry.Forest.Domains )
            foreach($DomainString in $DomainListAsString)
            {
                $domainList += @( [System.DirectoryServices.ActiveDirectory.DirectoryContext]::New("Domain", $DomainString) )
            }
            $DomainEntry.Dispose()
        }
        else
        {
            $domainList = @( $DomainContext )
        }
    }
    Process
    {
        $responseAll = @()
        foreach($Domain in $domainList)
        {
            $DomainEntry = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($Domain)

            $dcList = $DomainEntry.DomainControllers |
                Select-Object -ExpandProperty Name | Sort-Object

            foreach($dc in $dcList)
            {
                $ldapQuery = Measure-Command {
                    Test-NetConnection -ComputerName $dc -Port 389
                }
                $gcQuery = Measure-Command {
                    Test-NetConnection -ComputerName $dc -Port 3268
                }
                $response = New-Object -TypeName PsObject -Property @{
                    ComputerName = $dc
                    LdapResponseTime = $ldapQuery.TotalMilliseconds
                    GcResponseTime = $gcQuery.TotalMilliseconds
                }
                $responseAll += @( $response )
            }
            $DomainEntry.Dispose()
        }
        $responseAll
    }
}
