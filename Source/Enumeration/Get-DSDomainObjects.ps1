function Get-DSDomainObjects
{
<#
## Needs proper comment based help 

2017-09-04::0.1.1
- logic fixes
- updated default parameters output 

2017-09-01::0.1.0
- initial create
- count for user objects - break down by enabled, different ?uac sets
- count for computer objects - active/ stale :: pwdLastSet good here too

#>


    [CmdletBinding()]
    Param
    (  
        $Domain = $env:UserDomain,
        
        $UserMaxPwdAgeDays = 90,
        
        $ComputerMaxPwdAgeDays = 31,
        
        [ValidateRange(0,1000)]
        $PageSize = 500
    )
    
    Begin
    {  
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
        $DomainEntry = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        $DomainName = $DomainEntry.Name
        Write-Verbose "Domain name: $($DomainName)"
        $DomainEntry.Dispose()
        
        $ldapDomainPath = "LDAP://$($DomainName):389"
        
        $dateTimeUserMaxPwd = (Get-Date).AddDays(-$UserMaxPwdAgeDays)
        $dateTimeCompMaxPwd = (Get-Date).AddDays(-$ComputerMaxPwdAgeDays)
        $fileTimeUserMaxPwd = $dateTimeUserMaxPwd.ToFileTime()
        $fileTimeCompMaxPwd = $dateTimeCompMaxPwd.ToFileTime()
        
        
    }
    Process
    {
        $UserSet = New-Object -TypeName System.Collections.ArrayList

        $UserSearcher = [adsisearcher]($ldapDomainPath)
        $UserSearcher.SearchRoot = $ldapDomainPath
        $propertiesToLoad = @('distinguishedName','samaccountname','userAccountControl','pwdLastSet')
        $UserSearcher.PageSize = $PageSize
        
        $filterUsers = "(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=512))"
        
        $UserSearcher.Filter = $filterUsers
        
        [void]$UserSearcher.PropertiesToLoad.Clear()
        foreach($property in $propertiesToLoad)
        {
            [void]$UserSearcher.PropertiesToLoad.Add($property)
        }
        $UserResult = $UserSearcher.FindAll()
        foreach($object in $UserResult)
        {
            if( $object.Properties.pwdlastset[0] -ne 0 )
            {
                $PasswordLastSet = [dateTime]::FromFileTime($object.Properties.pwdlastset[0])
            }
            else
            {
                $PasswordLastSet = "0"
            }
            $uacAsInt =  $($object.Properties.useraccountcontrol)
            
            $objectTemp =  New-Object -TypeName PsObject -Property ([ordered]@{
                DistinguishedName   = $($object.properties.distinguishedname)
                SamAccountName      = $($object.properties.samaccountname)
                PasswordLastSet     = $PasswordLastSet
                UserAccountControl  = [int]$uacAsInt
            })
            [void]$UserSet.Add( $objectTemp )
        }
        
        #---
        
        $CompSet = New-Object -TypeName System.Collections.ArrayList
        
        $CompSearcher = [adsisearcher]($ldapDomainPath)
        $CompSearcher.SearchRoot = $ldapDomainPath
        $propertiesToLoad = @('distinguishedName','samaccountname','userAccountControl','pwdLastSet')
        $CompSearcher.PageSize = $PageSize
        
        $filterComp = "(objectCategory=computer)"
        
        $CompSearcher.Filter = $filterComp
        
        [void]$CompSearcher.PropertiesToLoad.Clear()
        foreach($property in $propertiesToLoad)
        {
            [void]$CompSearcher.PropertiesToLoad.Add($property)
        }
        $CompResult = $CompSearcher.FindAll()
        
        foreach($object in $CompResult)
        {
            if( $object.Properties.pwdlastset[0] -ne 0 )
            {
                $PasswordLastSet = [dateTime]::FromFileTime($object.Properties.pwdlastset[0])
            }
            else
            {
                $PasswordLastSet = "0"
            }
            $uacAsInt =  $($object.Properties.useraccountcontrol)
            
            $objectTemp =  New-Object -TypeName PsObject -Property ([ordered]@{
                DistinguishedName   = $($object.properties.distinguishedname)
                SamAccountName      = $($object.properties.samaccountname)
                PasswordLastSet     = $PasswordLastSet
                UserAccountControl  = [int]$uacAsInt
            })
            
            [void]$CompSet.Add( $objectTemp )
        }
        
        #---
        $SearchResults = New-Object -TypeName PsObject -Property ([ordered]@{
            Domain = $DomainName
            UserCount = $UserSet.Count
            UserEnabledAndActive = ($UserSet | Where-Object {(!($_.useraccountcontrol -band 2)) -and (!($_.useraccountcontrol -band 8388608 )) } ).count
            UserEnabled = ($UserSet | Where-Object { (!($_.useraccountcontrol -band 2)) }).count
            UserActive  = ($UserSet | Where-Object { ($_.PasswordLastSet -ge $dateTimeUserMaxPwd) -and (!($_.useraccountcontrol -band 8388608 )) } ).count # uac == passwordExpired
            UserActiveOther = ($UserSet | Where-Object { ($_.PasswordLastSet -lt $dateTimeUserMaxPwd) -and (!($_.useraccountcontrol -band 8388608 )) } ).count # uac == passwordExpired
            UserActiveDateAfter = $dateTimeUserMaxPwd
            UserUACValues = @( $UserSet | Select-Object -Unique -ExpandProperty UserAccountControl | Sort-Object )
            UserValues = $UserSet
            ComputerCount= $CompSet.count
            ComputerActive = ($CompSet | Where-Object {$_.PasswordLastSet -gt $dateTimeCompMaxPwd }).count
            ComputerEnabled = ($CompSet | Where-Object { (!($_.useraccountcontrol -band 2)) } ).count
            ComputerActiveDateAfter = $dateTimeCompMaxPwd
            ComputerUACValues = @( $CompSet | Select-Object -Unique -ExpandProperty UserAccountControl | Sort-Object )
            ComputerValues = $CompSet
        })
        $UserSearcher.Dispose()
        $CompSearcher.Dispose()
    }
    End
    {
        #--- formatting default display set
        $defaultDisplaySet = @(
            'Domain'
            'UserCount'
            'UserEnabledAndActive'
            'ComputerCount'
            'ComputerActive'
        )
        $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]$defaultDisplaySet)
        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@( $defaultDisplayPropertySet )
        $SearchResults.PsObject.TypeNames.Insert.(0,'Domain.ObjectPopulation')
        $SearchResults | Add-Member MemberSet PsStandardMembers $PSStandardMembers
        # Update-TypeData -TypeName 'Domain.ObjectPopulation' -DefaultDisplayPropertySet $defaultDisplaySet
        #--- end of formatting display set
        
        $SearchResults
    }
}