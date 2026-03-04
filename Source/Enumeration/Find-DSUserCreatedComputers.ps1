function Find-DSUserCreatedComputers
{
<#
.SYNOPSIS
Finds computer objects created by non-privileged users via ms-DS-CreatorSID.

.DESCRIPTION
Queries all computer objects for the ms-DS-CreatorSID attribute, which is populated only
when a non-administrative user creates the computer account (admin-created objects do not
have this attribute set). Resolves the SID to an account name and flags computers created
by accounts outside privileged groups. Useful for identifying attacker-created machine
accounts following a low-privilege domain join exploitation and for assessing RBCD attack
residue. Requires read access to the domain partition.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Find-DSUserCreatedComputers -Domain 'contoso.com'

Returns all computer objects with non-admin ms-DS-CreatorSID values in contoso.com.

.EXAMPLE
Find-DSUserCreatedComputers -Domain 'contoso.com' | Sort-Object -Property WhenCreated

Returns results sorted by creation date to identify recently joined rogue machines.

.NOTES
#### Name:    Find-DSUserCreatedComputers
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

        Write-Verbose "Finding user-created computer objects in domain: $DomainName"

        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $ldapPath = "LDAP://$domainDN"

        # ms-DS-CreatorSID is only set when created by a non-admin user
        $ldapFilter = '(&(objectClass=computer)(ms-DS-CreatorSID=*))'
        $properties = @(
            'name'
            'distinguishedName'
            'sAMAccountName'
            'ms-DS-CreatorSID'
            'whenCreated'
            'operatingSystem'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $queryResults = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties

        foreach ($obj in $queryResults)
        {
            $creatorSidRaw  = if ($null -ne $obj['ms-ds-creatorsid'] -and $obj['ms-ds-creatorsid'].Count -gt 0) { $obj['ms-ds-creatorsid'][0] } else { $null }
            $creatorSidStr  = $null
            $creatorAccount = $null

            if ($null -ne $creatorSidRaw)
            {
                try
                {
                    $sid           = New-Object System.Security.Principal.SecurityIdentifier($creatorSidRaw, 0)
                    $creatorSidStr = $sid.Value

                    try
                    {
                        $ntAccount     = $sid.Translate([System.Security.Principal.NTAccount])
                        $creatorAccount = $ntAccount.Value
                    }
                    catch
                    {
                        $creatorAccount = $creatorSidStr
                    }
                }
                catch
                {
                    Write-Verbose "Could not parse SID for '$([string]$obj['name'][0])': $_"
                    $creatorSidStr  = '<unparseable>'
                    $creatorAccount = '<unparseable>'
                }
            }

            $whenCreatedRaw = if ($null -ne $obj['whencreated'] -and $obj['whencreated'].Count -gt 0) { $obj['whencreated'][0] } else { $null }
            $whenCreated    = if ($null -ne $whenCreatedRaw) { try { [datetime]$whenCreatedRaw } catch { $null } } else { $null }

            [void]$results.Add(
                [PSCustomObject]@{
                    Name             = [string]$obj['name'][0]
                    SamAccountName   = [string]$obj['samaccountname'][0]
                    DistinguishedName = [string]$obj['distinguishedname'][0]
                    CreatorSID       = $creatorSidStr
                    CreatorAccount   = $creatorAccount
                    WhenCreated      = $whenCreated
                    OperatingSystem  = if ($null -ne $obj['operatingsystem'] -and $obj['operatingsystem'].Count -gt 0) { [string]$obj['operatingsystem'][0] } else { $null }
                    RiskLevel        = 'Medium'
                    Finding          = "Computer '$([string]$obj['name'][0])' was created by non-admin account '$creatorAccount'"
                }
            )
        }
    }

    End
    {
        $results | Sort-Object -Property WhenCreated -Descending
    }
}
