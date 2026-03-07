function Get-OSLevelDomainController
{
<#
2017-04-27::0.1.0
-initial creation, very quick polling function to get OS Version count from Domain Controllers
#>


    [CmdletBinding()]
    param
    (
        [String[]]
        $DomainList,
        
        [ValidateSet('2012','2012r2','2016')]
        $OSLevel = '2016'
    )
    
    Begin
    {
        $allDomainCoverage = @()
        $totalDomainView = New-Object -TypeName PsObject -Property ([ordered]@{
            domainName = "Totals"
            totalDCCount = 0
            targetOSCount = 0
            osCoverage = 0
            osCoverageAsPercent = 0
        })
        switch($OSLevel)
        {
            '2012' { $OSVerson = '6.2 (9200)' }
            '2012r2' { $OSVerson = '6.3 (9600)'}
            '2016' {$OSVerson = '10.0 (14393)'}
            default { $OSVerson = '10.0 (14393)'}
        }
        
    }
    Process
    {
        foreach($domain in $domainList)
        {
            $DCList = Get-AdDomainController -filter * -server $domain
            $osLevelTarget = @($DCList | Where-Object {$_.OperatingSystemVersion -eq $OSVerson} )
            
            $totalDCinDomain = $DCList.count
            $totalTargetDC = $osLevelTarget.count
            $coverageOfCurrentOS = $totalTargetDC / $totalDCinDomain
            $coverageOfCurrentOSFormatted = "{0:N4}" -f $coverageOfCurrentOS 
            $coverageOfCurrentOSPercent = "{0:P2}" -f $coverageOfCurrentOS
            
            # RiskLevel: low coverage of the target OS version means more DCs are running an
            # older (potentially unpatched or unsupported) OS level, increasing exposure.
            $osCoverageRisk = if ($coverageOfCurrentOS -ge 0.75) { 'Low' }
                              elseif ($coverageOfCurrentOS -ge 0.50) { 'Medium' }
                              else { 'High' }

            $domainOSCoverage = New-Object -TypeName PsObject -Property ([ordered]@{
                domainName = $domain
                totalDCCount = $totalDCinDomain
                targetOSCount = $totalTargetDC
                osCoverage = $coverageOfCurrentOSFormatted
                osCoverageAsPercent = $coverageOfCurrentOSPercent
                RiskLevel = $osCoverageRisk
            })
            
            $totalDomainView.totalDCCount += $totalDCinDomain
            $totalDomainView.targetOSCount += $totalTargetDC
            
            $allDomainCoverage += @($domainOSCoverage)
        }        
    }
    End
    {
        $totalCoverage = $($totalDomainView.targetOSCount) / $($totalDomainView.totalDCCount)
        $totalCoverageFormatted = "{0:N4}" -f $totalCoverage
        $totalCoveragePercent = "{0:P2}" -f $totalCoverage
        $totalDomainView.osCoverage = $totalCoverageFormatted
        $totalDomainView.osCoverageAsPercent = $totalCoveragePercent
        $allDomainCoverage += $($totalDomainView)
        $allDomainCoverage 
    }
}