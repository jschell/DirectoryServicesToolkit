function Get-DSKeyCredLink
{
<#
## Needs proper comment based help 
2017-11-29::0.1.1
- add 'size limit' parameter to allow result set scoping

2017-11-28::0.1.0
- initial create
#>


    [CmdletBinding()]
    Param
    (  
        $Domain = $env:UserDomain,
        
        [ValidateSet('All','MemberServer','Workstation')]
        $MachineType = 'All',

        
        [ValidateRange(0,10000)]
        $SizeLimit = 0,

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
        
        
    }
    Process
    {
        if(($MachineType -eq 'All') -OR ($MachineType -eq 'Workstation'))
        {
            $WorkstationSet = New-Object -TypeName System.Collections.ArrayList
    
            $WorkstationSearcher = [adsisearcher]($ldapDomainPath)
            $WorkstationSearcher.SearchRoot = $ldapDomainPath
            $propertiesToLoad = @('distinguishedName','samaccountname','userAccountControl','msDS-KeyCredentialLink')
            $WorkstationSearcher.PageSize = $PageSize
            $WorkstationSearcher.SizeLimit = $SizeLimit

            $filterWorkstations = "(&(objectcategory=computer) (!(operatingsystem=*server*) ) (!(useraccountcontrol:1.2.840.113556.1.4.803:=8192) ) (msds-KeyCredentialLink=*) )"
            
            $WorkstationSearcher.Filter = $filterWorkstations
            
            [void]$WorkstationSearcher.PropertiesToLoad.Clear()
            foreach($property in $propertiesToLoad)
            {
                [void]$WorkstationSearcher.PropertiesToLoad.Add($property)
            }
            $WorkstationResult = $WorkstationSearcher.FindAll()
            foreach($object in $WorkstationResult)
            {
                
                $uacAsInt =  $($object.Properties.useraccountcontrol)
                
                # RiskLevel: msDS-KeyCredentialLink on non-DC machines may indicate a Shadow
                # Credentials attack (ADCS ESC-adjacent) — an attacker who wrote this attribute
                # can authenticate as the computer account. High.
                $objectTemp =  New-Object -TypeName PsObject -Property ([ordered]@{
                    DistinguishedName   = $($object.properties.distinguishedname)
                    SamAccountName      = $($object.properties.samaccountname)
                    UserAccountControl  = [int]$uacAsInt
                    MachineType         = 'Workstation'
                    RiskLevel           = 'High'
                })
                [void]$WorkstationSet.Add( $objectTemp )
            }            
            $SearchResults += @($WorkstationSet)
            $WorkstationSearcher.Dispose()
        }
        
        #---
        if(($MachineType -eq 'All') -OR ($MachineType -eq 'MemberServer'))
        {
            $MemberServerSet = New-Object -TypeName System.Collections.ArrayList
            
            $MemberServerSearcher = [adsisearcher]($ldapDomainPath)
            $MemberServerSearcher.SearchRoot = $ldapDomainPath
            $propertiesToLoad = @('distinguishedName','samaccountname','userAccountControl','msDS-KeyCredentialLink')
            $MemberServerSearcher.PageSize = $PageSize
            $MemberServerSearcher.SizeLimit = $SizeLimit

            $filterMemberServer = "(&(objectcategory=computer) (operatingsystem=*server*) (!(useraccountcontrol:1.2.840.113556.1.4.803:=8192) ) (msds-KeyCredentialLink=*) )"
            
            $MemberServerSearcher.Filter = $filterMemberServer
            
            [void]$MemberServerSearcher.PropertiesToLoad.Clear()
            foreach($property in $propertiesToLoad)
            {
                [void]$MemberServerSearcher.PropertiesToLoad.Add($property)
            }
            $MemberServerResult = $MemberServerSearcher.FindAll()
            foreach($object in $MemberServerResult)
            {
                $uacAsInt =  $($object.Properties.useraccountcontrol)
                
                $objectTemp =  New-Object -TypeName PsObject -Property ([ordered]@{
                    DistinguishedName   = $($object.properties.distinguishedname)
                    SamAccountName      = $($object.properties.samaccountname)
                    UserAccountControl  = [int]$uacAsInt
                    MachineType         = 'MemberServer'
                    RiskLevel           = 'High'
                })
                [void]$MemberServerSet.Add( $objectTemp )
            }
            $SearchResults += @($MemberServerSet)    
            $MemberServerSearcher.Dispose()
        }
        
    }
    End
    {
        $SearchResults
    }
}