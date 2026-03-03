function Get-DSSelectiveAuth
{
<#
.Synopsis
Get computer objects with Selective Authentication configured.

.Description
By reading the Discretionary Acl on each computer object for the Allowed to Authenticate (Extended Right) right, a listing of objects granted the right can be built.

.Parameter Domain
Target domain to run the query against.

.Parameter PageSize
Page size for the search.

.Parameter Forest
Switch parameter, will search the entire forest for computer objects and build the A2A list.

.Example

PS> Get-DSSelectiveAuth -Domain contoso.com 

Name                Value
----                -----
ComputerName        TESTBOX
A2A                 {System.Collections.Hashtable, System.Collections.Hashtable}
DN                  CN=testbox,OU=Machines,DC=contoso,DC=com

Description
-----------
Returns the set of computer objects that have Selective Authentication enabled (in this case, one computer).

.Notes

Name:       Get-DSSelectiveAuth
Author:     J Schell
Version:    0.2.2
License:    MIT License

ChangeLog

2018-04-04::0.2.2
- updated to have proper help
- trimmed deprecated section

2018-04-04::0.2.1
- add counter for elapsed time 

2018-04-02::0.2.0
- adding securityMask dacl mask allows for reading ntsecuritydescriptor
- able to drop bgJobs idea

2018-04-02::0.1.1
- slow lookups with iterating on each item, bgJobs may help

2018-03-30::0.1.0
- initial create
#>


    [CmdletBinding()]
    Param
    (  
        $Domain = $env:UserDomain,
        
        [ValidateRange(0,1000)]
        $PageSize = 500,
        
        [Switch]
        $Forest
    )
    
    Begin
    {
        $invokeStart = get-date
        $DomainContext = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::New("Domain", $Domain)
        
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
        
        $allowedToAuthenticateGuid = '68b1d179-0d15-4d4f-ab71-46152e79a7bc'
    }
    Process
    {
        $computerA2AObjects = New-Object -TypeName System.Collections.ArrayList
        $allowedObjectSIDLookup = @{} # key = sid, value = nam
        
        foreach($targetDomain in $domainList)
        {
            try
            {
                $DomainEntry = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($targetDomain)
            }
            catch
            {
                Throw $_
            }
            
            $targetDomainName = $DomainEntry.Name
            $DomainEntry.Dispose()
            
            $targetlDAPDomainPath = "LDAP://$($targetDomainName):389"
            
            $propertiesToLoad = @('name','samaccountname','distinguishedname','ntsecuritydescriptor')
            $filter = "(objectClass=computer)"
            
            $computerObjSearch = [adsisearcher]($targetlDAPDomainPath)
            $computerObjSearch.SearchRoot = $targetlDAPDomainPath
            $computerObjSearch.PageSize = $PageSize
            $computerObjSearch.Filter = $filter
            $computerObjSearch.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl # required for getting ntsecuritydescriptor
            # $computerObjSearch.SizeLimit = 20 # for testing...
            
            [void]$computerObjSearch.PropertiesToLoad.Clear()
            foreach($property in $propertiesToLoad)
            {
                [void]$computerObjSearch.PropertiesToLoad.Add($property)
            }   
            
            $computerObjSearchResults = $computerObjSearch.FindAll()
            Write-Verbose "$($computerObjSearchResults.count)"
            
            $counterOfA2ACompObj = 0
            foreach($computer in $computerObjSearchResults)
            {
                $computerACE = ([System.Security.AccessControl.RawSecurityDescriptor]::new($computer.Properties.ntsecuritydescriptor[0],0)).DiscretionaryAcl
            
                $a2aCount = ($computerACE | where-object {$_.objectAceType -eq $allowedToAuthenticateGuid}).count
                if( $a2aCount -ge 1 )
                {
                    $counterOfA2ACompObj++
                    
                    $computerA2AObject = New-Object -TypeName PsObject @{
                        ComputerName    = $($computer.properties.name)
                        DN              = $($computer.properties.distinguishedname)
                        A2A             = @()    
                    }
                    foreach( $access in $computerACE )
                    {
                        if( $access.objectAceType -eq $allowedToAuthenticateGuid )
                        {
                            $a2aObj = New-Object -TypeName PsObject @{
                                IdentityAsName      = ''# $accessName
                                IdentityReference   = $($access.SecurityIdentifier.value)
                                IsInherited         = $($access.IsInherited)
                                InheritanceFlags    = $($access.InheritanceFlags)
                            }
                            $computerA2AObject.A2A += @($a2aObj)
                        }
                    }
                    [void]$computerA2AObjects.Add($computerA2AObject)
                }
                
                if( ($counterOfA2ACompObj % 100) -eq 0 )
                {
                    Write-Verbose "A2A computer rights found: $($counterOfA2ACompObj)"
                }
            }
            $computerObjSearch.Dispose()
            
            # moving sid translate to after collection
            $uniqueAllowed = @($computerA2AObjects.A2A.IdentityReference | Select-Object -Unique)
            foreach($allowedSID in $uniqueAllowed)
            {
                try
                {
                    $allowedSIDasSID = [System.Security.Principal.SecurityIdentifier]::new( $allowedSID )
                    $nameFromSID = ($allowedSIDasSID.Translate([System.Security.Principal.NTAccount])).value
                    $allowedObjectSIDLookup.Add( $allowedSID, $nameFromSID )
                }
                catch
                {
                    $allowedObjectSIDLookup.Add( $allowedSID, $allowedSID )
                }
            }
            foreach( $computerA2AObject in $computerA2AObjects)
            {
                foreach( $access in $($computerA2AObject.A2A) )
                {
                    $access.IdentityAsName = $allowedObjectSIDLookup.($($access.IdentityReference))
                }
            }
            # sid translate completed
        }
    }
    End
    {
        $invokeComplete = get-date
        $timeToComplete = $invokeComplete - $invokeStart
        Write-Verbose "Time to complete: $($timeToComplete.ToString())"
        $computerA2AObjects
    }
}