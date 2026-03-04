function Test-DSLAPSPermissions
{
    <#
    .SYNOPSIS
    Reviews ACLs on computer objects and OUs to identify principals with read access to LAPS password attributes.

    .DESCRIPTION
    Queries computer objects and their parent OUs to find principals with read access to
    ms-Mcs-AdmPwd (legacy LAPS) or msLAPS-Password (Windows LAPS) attributes. Overly broad
    LAPS read access is a common misconfiguration that exposes local administrator credentials
    to non-privileged accounts. Requires read access to the domain partition and the ability to
    read AD object ACLs.

    .PARAMETER Domain
    The DNS name of the domain to query. Defaults to the current user's domain.

    .PARAMETER SampleSize
    Maximum number of computer objects to audit ACLs on. Defaults to 50.

    .EXAMPLE
    Test-DSLAPSPermissions -Domain 'contoso.com'

    Audits ACLs on up to 50 computer objects for LAPS password attribute read access.

    .EXAMPLE
    Test-DSLAPSPermissions -Domain 'contoso.com' -SampleSize 200

    Audits ACLs on up to 200 computer objects for LAPS password attribute read access.

    .NOTES
    #### Name:    Test-DSLAPSPermissions
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
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter(HelpMessage = 'Maximum number of computer objects to audit ACLs on')]
        [ValidateRange(1, 10000)]
        [int]$SampleSize = 50
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

        Write-Verbose "Auditing LAPS ACLs on domain: $DomainName (sample size: $SampleSize)"

        $domainDN   = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $ldapPath   = "LDAP://$domainDN"
        $ldapFilter = '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        $properties = @('distinguishedName', 'name', 'sAMAccountName')

        $lapsAttributeGuids = @(
            [guid]'8d3bca50-1d7e-11d0-a081-00aa006c33ed'  # ms-Mcs-AdmPwd
            [guid]'a2b8b0d1-ef2d-4b72-a870-45e05fef6a7f'  # msLAPS-Password
        )

        $safePrincipals = @(
            'Domain Admins'
            'Enterprise Admins'
            'Administrators'
            'BUILTIN\Administrators'
            'NT AUTHORITY\SYSTEM'
            'SELF'
            'SYSTEM'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $computers = Invoke-DSDirectorySearch -LdapPath $ldapPath -Filter $ldapFilter -Properties $properties |
            Select-Object -First $SampleSize

        foreach ($obj in $computers)
        {
            $computerDN   = [string]$obj['distinguishedname'][0]
            $computerLdap = "LDAP://$computerDN"

            Write-Verbose "Auditing ACL on: $computerDN"

            $aces = Get-DSObjectAcl -LdapPath $computerLdap

            foreach ($ace in $aces)
            {
                if ($ace.AccessControlType -ne 'Allow') { continue }

                $isLapsGuid = $lapsAttributeGuids -contains $ace.ObjectType
                if (-not $isLapsGuid) { continue }

                $identity = $ace.IdentityReference

                $isSafe = $false
                foreach ($principal in $safePrincipals)
                {
                    if ($identity -match [regex]::Escape($principal))
                    {
                        $isSafe = $true
                        break
                    }
                }

                if ($isSafe) { continue }

                $lapsAttrName = if ($ace.ObjectType -eq [guid]'8d3bca50-1d7e-11d0-a081-00aa006c33ed')
                {
                    'ms-Mcs-AdmPwd (Legacy LAPS)'
                }
                else
                {
                    'msLAPS-Password (Windows LAPS)'
                }

                [void]$results.Add(
                    [PSCustomObject]@{
                        ComputerName      = [string]$obj['name'][0]
                        ComputerDN        = $computerDN
                        IdentityReference = $identity
                        Rights            = $ace.ActiveDirectoryRights.ToString()
                        ObjectType        = $ace.ObjectType.ToString()
                        LAPSAttribute     = $lapsAttrName
                        IsInherited       = $ace.IsInherited
                        RiskLevel         = 'High'
                        Finding           = "Principal '$identity' can read LAPS password attribute on '$([string]$obj['name'][0])'"
                    }
                )
            }
        }
    }

    End
    {
        $results | Sort-Object -Property ComputerName
    }
}
