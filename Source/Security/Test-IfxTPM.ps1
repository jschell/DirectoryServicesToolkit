Function Test-IfxTpm
{
<#
.SYNOPSIS
Tests if a Windows system has an enabled Trusted Platform Module (TPM) that is
vulnerable to CVE-2017-15361.

.DESCRIPTION
Tests if a Windows system has an enabled Trusted Platform Module (TPM) that is
vulnerable to CVE-2017-15361. Must be run with administrator privileges against
machine(s) in scope.

.PARAMETER ComputerName
Specifies the computer or computers to run the check against. Defaults to local
system.

.EXAMPLE
PS > Test-IfxTpm

ComputerName  VulnFirmware InfineonTPM Checked Error
------------  ------------ ----------- ------- -----
myComputer           False       False    True False

Description
-----------
Test was run with no user specified target, defaulting to run against local
system (named 'myComputer'). The system was checked and the results were returned.

.EXAMPLE
PS > Test-IfxTpm -ComputerName $env:ComputerName

ComputerName  VulnFirmware InfineonTPM Checked Error
------------  ------------ ----------- ------- -----
myComputer           False       False    True False

Description
-----------
Test was run using the local system as a target (named 'myComputer'). The
system was checked and the results were returned.

.INPUTS
System.String, System.Array

.OUTPUTS
PsCustomObject

.LINK
https://github.com/iadgov/Detect-CVE-2017-15361-TPM

.LINK
https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV170012

.NOTES

#### Name:       Test-IfxTpm
#### Author:     J Schell
#### Version:    0.1.3
#### License:    MIT

### Change Log


##### 2017-11-15::0.1.3
- modify default display properties and sort key for objects

##### 2017-11-15::0.1.2
- return status of error in output object

##### 2017-11-15::0.1.1
- error handling for insufficient access using Error Variable

##### 2017-11-15::0.1.0
- intial creation
#>


    [OutputType([PsCustomObject])]
    [CmdletBinding()]
    Param
    (
        [Parameter(ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $True)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ComputerName = $env:COMPUTERNAME
    )

    Begin
    {
        $InfineonManufacturerId = 0x49465800
        $statusResult = @()
    }
    Process
    {
        foreach($computer in $ComputerName)
        {
            $computerStatus = New-Object -TypeName psobject -Property ([ordered]@{
                ComputerName =  $computer
                VulnFirmware =  $False
                InfineonTPM =   $False
                Checked     =   $False
                Error       =   $False
                RiskLevel   =   'Unknown'
            })

            #---StartOfPropertyDisplayFormatting
            $defaultDisplaySet = @(
                'ComputerName'
                'VulnFirmware'
                'Checked'
            )
            $defaultKeyPropertySet = @(
                'Checked'
                'VulnFirmware'
                'ComputerName'
            )

            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]$defaultDisplaySet)
            $defaultDisplayKeySet = New-Object System.Management.Automation.PSPropertySet('DefaultKeyPropertySet', [string[]]$defaultKeyPropertySet)
            $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@( $defaultDisplayPropertySet, $defaultDisplayKeySet )
            $computerStatus.PsObject.TypeNames.Insert(0,'Computer.IfxTPM')
            $computerStatus | Add-Member MemberSet PsStandardMembers $PSStandardMembers
            #---EndOfPropertyDisplayFormatting

            $tpmParam = @{
                ClassName = "Win32_TPM"
                Namespace = "root/cimv2/Security/MicrosoftTPM"
                ComputerName = $computer
                ErrorAction = "SilentlyContinue"
                ErrorVariable = "TPMQueryIssue"
            }

            $tpmDetail = Get-CimInstance @tpmParam

            if( !($TPMQueryIssue) )
            {
                $computerStatus.Checked = $True
            }
            else
            {
                $computerStatus.Error = $True
            }

            if($tpmDetail)
            {
                $computerStatus.Checked = $True
                if($tpmDetail.ManufacturerId -eq $InfineonManufacturerId)
                {
                    $computerStatus.InfineonTPM = $True
                    $IfxFirmwareVersion = [System.Version]$tpmDetail.ManufacturerVersion
                    switch($IfxFirmwareVersion.Major)
                    {
                        4
                        {
                            $computerStatus.VulnFirmware = (($IfxFirmwareVersion.Minor -le 33) -OR
                                ($IfxFirmwareVersion.Minor -ge 40 -AND $IfxFirmwareVersion.Minor -le 42))
                        }
                        5
                        {
                            $computerStatus.VulnFirmware = ($IfxFirmwareVersion.Minor -le 61)
                        }
                        6
                        {
                            $computerStatus.VulnFirmware = ($IfxFirmwareVersion.Minor -le 42)
                        }
                        7
                        {
                            $computerStatus.VulnFirmware = ($IfxFirmwareVersion.Minor -le 61)
                        }
                        133
                        {
                            $computerStatus.VulnFirmware = ($IfxFirmwareVersion.Minor -le 32)
                        }
                        default
                        {
                            $computerStatus.VulnFirmware = $False
                        }
                    }
                }
            }
            # RiskLevel: CVE-2017-15361 (ROCA) allows RSA private key reconstruction from the
            # public key when generated by a vulnerable Infineon firmware. This compromises any
            # certificate or BitLocker key backed by the TPM.
            $computerStatus.RiskLevel = if ($computerStatus.Error)
            {
                'Unknown'
            }
            elseif ($computerStatus.VulnFirmware)
            {
                'High'
            }
            elseif ($computerStatus.InfineonTPM)
            {
                'Low'
            }
            else
            {
                'Informational'
            }

            $statusResult += @($computerStatus)
        }
    }
    End
    {
        $statusResult
    }
}
