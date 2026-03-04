function Test-DSADCSACL
{
<#
.SYNOPSIS
Reviews ACLs on Enterprise CA objects for dangerous permissions (ESC7).

.DESCRIPTION
Reviews the ACL on each Enterprise CA object in the Enrollment Services container
for overly permissive permissions. Principals outside built-in administrative groups
with ManageCA (ESC7) or ManageCertificates rights can issue arbitrary certificates
or escalate privileges.

Requires read access to the Configuration naming context and the ability to read
AD object ACLs.

.PARAMETER Domain
The DNS name of the domain to query. Defaults to the current user's domain.

.EXAMPLE
Test-DSADCSACL -Domain 'contoso.com'

Returns all ACEs on Enterprise CA objects in contoso.com that grant ManageCA or
ManageCertificates rights to non-administrative principals.

.EXAMPLE
Test-DSADCSACL -Domain 'contoso.com' | Where-Object { $_.Permission -eq 'ManageCA' }

Filters results to only those ACEs granting the ManageCA extended right (ESC7).

.NOTES
#### Name:    Test-DSADCSACL
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

        Write-Verbose "Querying domain: $DomainName for CA ACL misconfigurations"

        $domainDN      = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $configNC      = "CN=Configuration,$domainDN"
        $enrollSvcPath = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"

        # Extended right GUIDs
        $manageCAGuid             = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        $manageCertificatesGuid   = '0e10c968-78fb-11d2-90d4-00c04f79dc55'

        # Well-known safe principals — exclude from flagging
        $safePrincipals = @(
            'S-1-5-18'
            'S-1-5-32-544'
            'Enterprise Admins'
            'Domain Admins'
            'Administrators'
            'BUILTIN\Administrators'
            'NT AUTHORITY\SYSTEM'
        )

        $ldapFilter = '(objectClass=pKIEnrollmentService)'
        $properties = @(
            'name'
            'distinguishedName'
        )

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        $caObjects = Invoke-DSDirectorySearch -LdapPath $enrollSvcPath -Filter $ldapFilter -Properties $properties

        foreach ($obj in $caObjects)
        {
            $caName = [string]$obj['name'][0]
            $caDN   = [string]$obj['distinguishedname'][0]

            Write-Verbose "Reviewing ACL on CA: $caName"

            $acl = Get-DSObjectAcl -DistinguishedName $caDN

            foreach ($ace in $acl)
            {
                if ($ace.AccessControlType -ne 'Allow')
                {
                    continue
                }

                $identity = $ace.IdentityReference.ToString()

                # Skip well-known safe principals
                $isSafe = $false
                foreach ($safe in $safePrincipals)
                {
                    if ($identity -like "*$safe*" -or $identity -eq $safe)
                    {
                        $isSafe = $true
                        break
                    }
                }

                if ($isSafe)
                {
                    continue
                }

                $objectTypeGuid = $ace.ObjectType.ToString().ToLower()
                $permName       = $null

                if ($objectTypeGuid -eq $manageCAGuid)
                {
                    $permName = 'ManageCA'
                }
                elseif ($objectTypeGuid -eq $manageCertificatesGuid)
                {
                    $permName = 'ManageCertificates'
                }

                if ($null -eq $permName)
                {
                    continue
                }

                [void]$results.Add(
                    [PSCustomObject]@{
                        CAName              = $caName
                        CADistinguishedName = $caDN
                        IdentityReference   = $identity
                        Rights              = $ace.ActiveDirectoryRights.ToString()
                        ObjectType          = $ace.ObjectType.ToString()
                        Permission          = $permName
                        IsInherited         = $ace.IsInherited
                        RiskLevel           = 'High'
                        Finding             = "Non-admin principal '$identity' has $permName rights on CA '$caName' (ESC7)"
                    }
                )
            }
        }
    }

    End
    {
        $results.ToArray()
    }
}
