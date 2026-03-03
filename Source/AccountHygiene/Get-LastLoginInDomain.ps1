function Get-LastLogonInDomain
{
<#
.SYNOPSIS
Get the value of 'lastlogon' attribute from one or more user accounts

.DESCRIPTION
Collects the highest (most recent) value of 'lastlogon' from one or more domain
controllers. For completeness, this non-indexed, non-replicated attribute must 
be checked against all domain controllers in the domain.

.PARAMETER DomainController
Specifies the DomainController or DomainControllers to run the check against. 
Defaults to local system.

.PARAMETER sAMAccountName
Specifies the samaccountname(s) to get most recent lastlogon attribute.

.PARAMETER LDAPQueryMergeSize
Specifies the number of objects that will be concantenated together in a 
single query. This has an arbitrary limit of 500, actual limit is more likely
to be 10s of 1000s.

.EXAMPLE
PS > Get-LastLogonInDomain -DomainController pdc01 -sAMAccountName jdoe

Name  Value
----  -----
jdoe  @{sAMAccountName=jdoe; DistinguishedName=CN=John Doe,DC=Contoso,DC=com,lastlogon=0}

Description
-----------
Searching for the last logon time for user 'jdoe' on domain controller 'pdc01' returned
a value of '0' (never logged on to that domain controller).

.EXAMPLE
PS > Get-LastLogonInDomain -DomainController pdc01,bdc02,bdc03 -sAMAccountName jdoe

Name  Value
----  -----
jdoe  @{sAMAccountName=jdoe; DistinguishedName=CN=John Doe,DC=Contoso,DC=com,lastlogon=2017-02-29 14:39:01 }

Description
-----------
Searching for the last logon time for user 'jdoe' on domain controller 'pdc01',
'bdc02' and 'bdc03' returned a value of '2017-02-29 14:39:01'.

.INPUTS
System.String, System.Array

.OUTPUTS
System.Collections.HashTable

.NOTES

#### Name:       Get-LastLogonInDomain
#### Author:     J Schell
#### Version:    0.2.1
#### License:    MIT

### Change Log

##### 2018-01-18::0.2.1
- renamed 'PageSize' to 'LDAPQueryMergeSize'

##### 2018-01-18::0.2.0
- Reworked query structure, merging multiple samAccountName queries into single
'or' query to reduce the number of calls per domain controller. Arbitrarily
limiting the poorly named 'PageSize' parameter to max of 500. LDAP query size
can be larger, although consequenses of breaching the limit (10Mb) have 
significant impact on target DC (it will melt).

##### 2018-01-17::0.1.4
- landed on naive/ simple pattern of dcPopulation (search/test is removed), 
assume user that invoke will have current, good list of dcTargets.

##### 2018-01-17::0.1.3
- containsKey validation/ adding moved inside [objQuery.count -eq 1]

##### 2018-01-17::0.1.2
- comment out section using search-dsdomaincontroller and test-portasjob, 
testing functionality w/o invoking cost for search each time

##### 2018-01-16::0.1.1
- moved domaincontroller to standalone section

##### 2018-01-16::0.1.0
- intial creation
#>


    [OutputType([System.Collections.HashTable])]
    [CmdletBinding()]
    Param
    (    
        [string[]]
        $DomainController = $env:ComputerName,
        
        [string[]]
        $sAMAccountName = $env:UserName,
        
        [ValidateSet(10,20,50,100,200,500)]
        $LDAPQueryMergeSize = 10
    )
    Begin
    {
        $domainControllerPopulation = $DomainController
            
        $userLastLogonData = @{}
        $propertiesToLoad = @(
            'distinguishedname'
            'samaccountname'
            'lastlogon'
        )
        
        #Below should be moved to entirely separate function
        #---Filter merger magic section
        $lDAPFilterSet = @()
        $stepCurrent = 0
        $stepBegin = $stepCurrent
        $stepEnd = $stepBegin + ($LDAPQueryMergeSize -1)

        if($stepEnd -ge ($sAMAccountName.Count -1))
        {
            $stepEnd = $sAMAccountName.Count - 1
        }
        do
        {
            $finalSet = $False
            $filterBody = ""
            do
            {
                $user = "$($sAMAccountName[$stepCurrent])"
                $filterBody = $filterBody + '(samaccountname=' + $user + ')'
                $stepCurrent++
            }
            while( $stepCurrent -le $stepEnd ) 

            $filterBody = '(|' + $filterBody + ')'
            $lDAPFilterSet += @( $filterBody )

            $stepBegin = $stepCurrent
            $stepEnd = $stepBegin + ($LDAPQueryMergeSize -1)

            if($stepEnd -ge ($sAMAccountName.Count -1))
            {
                $stepEnd = $sAMAccountName.Count - 1
                $finalSet = $True
                $filterBody = ""
                do
                {
                    $user = "$($sAMAccountName[$stepCurrent])"
                    $filterBody = $filterBody + '(samaccountname=' + $user + ')'
                    $stepCurrent++
                }
                while( $stepCurrent -le $stepEnd ) 
                $filterBody = '(|' + $filterBody + ')'
                $lDAPFilterSet += @( $filterBody )
            }
        }
        while($finalSet -ne $True )
        #---End filter merger magic section
    }
    Process
    {
        foreach($dcTarget in $domainControllerPopulation)
        {
            Write-Verbose "Currently on $($dcTarget)"
            
            $lDAPTarget = "LDAP://$($dcTarget):389"
            
            foreach($filter in $lDAPFilterSet)
            {
                Write-Verbose "$($filter)"
                $SearchObject = [adsisearcher]($lDAPTarget)
                $SearchObject.SearchRoot = $lDAPTarget
                $SearchObject.Filter = $filter

                [void]$SearchObject.PropertiesToLoad.Clear()
                foreach($property in $propertiesToLoad)
                {
                    [void]$SearchObject.PropertiesToLoad.Add($property)
                }
                $ObjectQuery = $SearchObject.FindAll()

                foreach($userFound in $ObjectQuery)
                {
                    if($userFound.Properties.lastlogon)
                    {
                        $lastLogonFileTime = $userFound.Properties.lastlogon[0]
                    }
                    else
                    {
                        $lastLogonFileTime = 0
                    }
                
                    $userDetail = New-Object -TypeName PsObject -Property @{
                        DistinguishedName   = $userFound.Properties.distinguishedname[0]
                        sAMAccountName      = $userFound.Properties.samaccountname[0]
                        LastLogon           = $lastLogonFileTime
                    }
                    
                    if($userLastLogonData.ContainsKey( $userDetail.sAMAccountName) )
                    {
                        If( $userLastLogonData[$userDetail.sAMAccountName].lastlogon -lt  $userDetail.lastlogon )
                        {
                            $userLastLogonData[$userDetail.sAMAccountName].lastlogon =  $userDetail.lastlogon
                        }
                    }
                    else
                    {
                        $userLastLogonData.Add( $userDetail.samaccountname,($userDetail | 
                            Select-Object sAMAccountName, DistinguishedName, lastlogon) )
                    }
                }
                
                $SearchObject.Dispose()
            }
        }
    }
    End
    {
        $userLastLogonData.Values | ForEach-Object {
            if( $_.lastlogon -gt 0 )
            {
                $_.lastlogon = [datetime]::FromFileTime( $_.lastlogon )
            }
        }
        $userLastLogonData
    }
}