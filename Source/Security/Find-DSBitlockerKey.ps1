function Find-DSBitlockerKey
{
<#
nesting Get-msFVEObject within function to control exposed data...
2017-08-24::0.1.0
#>


    [CmdletBinding()]
    [OutputType([PSObject])]
    Param
    (
        $Domain = $env:UserDomain,
        
        [Parameter( Mandatory = $True )]
        [ValidatePattern("\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}")]
        [string[]]
        $KeyCheck
    )

    Begin
    {
        function Get-msFVEObject
        {
        <#
        update to use system.collections.arraylist - leverage .add() method

        cannot be run from constrained lang mode environment, must have access to full language

        pro tip - if you get the pageSize, _set_ the pageSize (whoops)

        #>


            [CmdletBinding()]
            Param
            (
                
                $Domain = $env:UserDomain,
                
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
                # $QueryResult = @()
                $QueryResult = New-Object -TypeName System.Collections.ArrayList
                
                $Searcher = [adsisearcher]($ldapDomainPath)
                $propertiesToLoad = @('distinguishedName', 'msFVE-RecoveryPassword')
                $Searcher.Filter = "(objectClass=msFVE-RecoveryInformation)"
                $Searcher.PageSize = $PageSize
                
                $Searcher.PropertiesToLoad.Clear() | out-null
                foreach($property in $propertiesToLoad)
                {
                    $Searcher.PropertiesToLoad.Add($property) | out-null
                }
                
                $Result = $Searcher.FindAll()
                [void]$Result.Count
                Write-Verbose "Total obj: $($Result.Count)"
                if( $($Result.Count) -ge 1 )
                {
                    foreach( $object in $Result )
                    {
                        $simpleObject = New-Object -TypeName PsObject -Property @{
                            distinguishedName   = $object.Properties.distinguishedname
                            RecoveryPassword    = $object.Properties.'msfve-recoverypassword'
                            ParentObject        = $object.Properties.distinguishedname.Split('}')[1].Trim(',')
                        }
                        [void]$QueryResult.Add($simpleObject)
                    }
                }
                else
                {
                    Write-Error "No objects returned! Verify access."
                    Break
                }
                $Searcher.Dispose()
                
            }
            End
            {
                $QueryResult
            }
            
        }
    }
    Process
    {
        Write-Verbose "Initial loading of objects can take several minutes..."
        $script:ValidKeys = Get-msFVEObject -Domain $Domain
        Write-Verbose "Objects loaded, checking if keys are valid..."
        
        $ResultSet = $null
        foreach($Key in $KeyCheck)
        {
            $KeyResult = @( $ValidKeys.Where({ $_.RecoveryPassword -eq  $Key }) )
            if( $KeyResult.Count -ge 1 )
            {
                $KeyValid = $True
                $KeyComputer = $KeyResult.ParentObject
            }
            else
            {
                $KeyValid = $False
                $KeyComputer = $null
            }
            
            $KeyObject = New-Object -TypeName PsObject -Property ([ordered]@{
                Key     = $Key
                Valid   = $KeyValid
                Computer= $KeyComputer
            })
            $ResultSet += @( $KeyObject )
        }
    }
    End
    {
        $ResultSet
    }
}