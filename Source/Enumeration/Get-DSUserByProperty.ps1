function Get-DSUserByProperty
{
<#
.SYNOPSIS
Search for users in the directory.

.DESCRIPTION
Using native System.DirectoryServices, searches the directory (default is to use 
the global catalog) for entries that match 

.PARAMETER TargetDomain
Specifies the domain to run the search against.

.PARAMETER UserName
Specifies one or more items identifying users by a single property. Examples could
include a list of users by display name, sam account name, mail, or user principal name.

.PARAMETER Property
Specifies the property to search against, from a common set of properties.

.PARAMETER PropertyUserDefined
Specifies the property to search against, defined at time of invocation. Property
value will be checked against the schema of the TargetDomain. Using this parameter 
may introduce a delay at the beginning of invocation, while the list of indexed 
user properties is collected.

.PARAMETER UseLDAP
Switch parameter, directs the search to target only the (local) directory, not
the global catalog.

.EXAMPLE
PS > Get-DSUserByProperty -UserName jdoe@Contoso.com -Property mail

alias             : jdoe
displayname       : John Doe (Product Dev)
mail              : jdoe@contoso.com
title             : Product Development Researcher
userprincipalname : jdoe@contoso.com
manager           : alicesm
managerMail       : alice.smith@contoso.com
department        : Widget Research

Description
-----------
Searching for users that have 'jdoe@contoso.com' as the mail attribute.

.EXAMPLE
PS > $listOfUsers = @( "jdoe", "alicesm", "charlesf", "ericalewis")
PS > Get-DSUserByProperty -UserName $listOfUsers -Property samaccountname

WARNING: Could not find ericalewis

alias             : jdoe
displayname       : John Doe (Product Dev)
mail              : jdoe@contoso.com
title             : Product Development Researcher
userprincipalname : jdoe@contoso.com
manager           : alicesm
managerMail       : alice.smith@contoso.com
department        : Widget Research

alias             : alicesm
displayname       : Alice Smith (Widget Manager)
mail              : alice.smith@contoso.com
title             : Widget Manager
userprincipalname : alicesm@contoso.com
manager           : erical
managerMail       : ericalewis@contoso.com
department        : Adminstration

alias             : charlesf
displayname       : Charles Fox (Internet Janitor)
mail              : charlesfox@contoso.com
title             : Internet Janitor
userprincipalname : charlesf@contoso.com
manager           : alicesm
managerMail       : alice.smith@contoso.com
department        : Cloud Sanitation

Description
-----------
Given an array of values, searches for each entry using the specified property. In
this example, the entry 'ericalewis' did not match the samaccountname of any user, as
indicated by the warning.
 
.INPUTS
System.String

.OUTPUTS
PSCustomObject

.LINK
about_comment_based_help

.NOTES

#### Name:     Get-DSUserByProperty
#### Author:   J Schell
#### Version:  0.1.1
#### License:  MIT License

### Change Log

##### 2017-02-10::0.1.1
-logic fix for results that have more than one object returned.

##### 2017-02-10::0.1.0
-initial creation
-fork/ consolidation of multiple versions of lookup by 'x' property on users

#>


    [CmdletBinding(DefaultParameterSetName = "CommonProperty")]
    [OutputType([PSObject[]])]
    Param
    (
        [Parameter(Mandatory = $False,
            ParameterSetName = "__AllParameterSets")]
        [String]
        $TargetDomain = $env:USERDNSDOMAIN,
        
        [Parameter(Mandatory = $True,
            ParameterSetName = "__AllParameterSets")]
        [String[]]
        $UserName,
        
        [Parameter(Mandatory = $True,
            ParameterSetName = "CommonProperty")]
        [ValidateSet("samaccountname","displayname","mail","userprincipalname")]
        [String]
        $Property,
        
        [Parameter(Mandatory = $True,
            ParameterSetName = "UserDefinedProperty")]
        [String]
        $PropertyUserDefined,

        [Parameter(Mandatory = $False)]
        [Switch]
        $UseLDAP
    )
    
    Begin
    {
        $DomainContext = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::New("Domain", $TargetDomain)
        Try 
        {
            $DomainEntry = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        Catch 
        {
            Write-Error $_
            Break
        }

        if( $PropertyUserDefined )
        {
            $ForestContext = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::New("Forest", $($DomainEntry.Forest.Name) )
            
            $Schema = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetSchema($ForestContext)
            $userMandatoryProperties = @( $Schema.FindClass("User").MandatoryProperties | 
                Where-Object {$_.isIndexed -eq $True} | 
                Select-Object -ExpandProperty Name )
            $userOptionalProperties = @( $Schema.FindClass("User").OptionalProperties | 
                Where-Object {$_.isIndexed -eq $True} | 
                Select-Object -ExpandProperty Name )
            
            $Schema.Dispose()

            $userProperties = @( $userMandatoryProperties )
            $userProperties += @( $userOptionalProperties )

            $msgUserPropertiesIndexedFoundInSchema = "Properties found: $($userProperties.count)"
            Write-Verbose $msgUserPropertiesIndexedFoundInSchema

            if( $userProperties -contains $PropertyUserDefined)
            {
                
                $PropertyToSearch = $PropertyUserDefined
            }
            else
            {
                $msgPropertyUserDefinedNotInSchema = "The property `'$($PropertyUserDefined)`'' " +
                    "was not found as a property for the user class in the schema."
                Write-Error $msgPropertyUserDefinedNotInSchema
                Break
            }
        }
        else
        {
            $PropertyToSearch = $Property
        }
        Write-Output "Search on: $($PropertyToSearch)"
        
        if($UseLDAP)
        {
            $TargetSearch = "LDAP://$($DomainEntry.Name):389"
        }
        else 
        {
            $TargetSearch = "GC://$($DomainEntry.Name):3268"
        }
        $DomainEntry.Dispose()
    }
    Process
    {
        $UsersFound = @()

        foreach($User in $UserName)
        {
            $adsiTarget = [adsi]$TargetSearch
            $Searcher = [adsisearcher]($adsiTarget)
            $ldapFilter = "(&(objectClass=user)($PropertyToSearch=$User))"
            $Searcher.Filter = $ldapFilter
            $SearchResult = $Searcher.FindAll()

            if( $($SearchResult.Count) -ge 1)
            {
                foreach($Result in $SearchResult)
                {
                    if( $($Result.Properties.manager) )
                    {
                        $UserManagerPath = [ADSI]"LDAP://$($Result.Properties.manager)"
                        $UserManagerAlias = $($UserManagerPath.Properties.samaccountname)
                        $UserManagerMail =  $($UserManagerPath.Properties.mail)
                    }
                    else
                    {
                        $UserManagerAlias = "UnDef"
                        $UserManagerMail = ""
                    }
                    $UserFound = New-Object -TypeName PsObject -Property ([ordered]@{
                        samaccountname = $($Result.Properties.samaccountname)
                        displayname = $($Result.Properties.displayname)
                        mail = $($Result.Properties.mail)
                        title = $($Result.Properties.title)
                        department = $($Result.Properties.department)
                        userprincipalname = $($Result.Properties.userprincipalname)
                        manager = $UserManagerAlias
                        managerMail = $UserManagerMail
                    })
                    $UsersFound += @( $UserFound )
                }
            }    
            else
            {
                Write-Warning "Could not find $($User)"
            }
            $Searcher.Dispose()
        }
    }
    End
    {
        [PSObject[]]$UsersFound
    }
}