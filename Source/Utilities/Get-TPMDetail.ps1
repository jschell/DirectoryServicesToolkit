Function Get-TpmDetail
{
<#
.SYNOPSIS
Get details of TPM chip

.DESCRIPTION
Get details of TPM chip

.PARAMETER ComputerName
Specifies the computer or computers to run the check against. Defaults to local 
system.

.EXAMPLE
PS > Get-TpmDetail -ComputerName $env:ComputerName | format-list * 

ComputerName : myComputer

Description
-----------

.INPUTS
System.String, System.Array

.OUTPUTS
PsCustomObject


.LINK
https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Version-1.01-Revision-1.00.pdf 

.NOTES

#### Name:       Get-TpmDetail
#### Author:     J Schell
#### Version:    0.1.2
#### License:    MIT

### Change Log


##### 2018-06-06::0.1.2
- removed defaultPropertySet section, doesn't work in constrained lang mode...

##### 2018-06-06::0.1.1
- need to use 'specVer', not 'phyPresVerInfo'
- split and extract relevant section for use...

##### 2018-06-04::0.1.0
- intial creation
- rework of test-ifxTPM
#>
    
    
    [OutputType([PsCustomObject])]
    [OutputType([System.Array])]
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
        #from TCG Vendor ID Registry
        
        $vendorList = @"
        TPMVendor, TPMVendorID, TPMVendorIDDec
        AMD, 0x414D4400, 1095582720
        Atmel, 0x41544D4C, 1096043852
        Broadcom, 0x4252434D, 1112687437
        HPE, 0x48504500, 1213220096
        IBM, 0x49424d00, 1229081856
        Infineon, 0x49465800, 1229346816
        Intel, 0x494E5443, 1229870147
        Lenovo, 0x4C454E00, 1279610368
        Microsoft, 0x4D534654, 1297303124
        National Semiconductor, 0x4E534D20, 1314082080
        Nationz, 0x4E545A00, 1314150912
        Nuvoton Technology, 0x4E544300, 1314145024
        Qualcomm, 0x51434F4D, 1363365709
        SMSC, 0x534D5343, 1397576515
        ST Microelectronics, 0x53544D20, 1398033696
        Samsung, 0x534D534E, 1397576526
        Sinosun, 0x534E5300, 1397641984
        Texas Instruments, 0x54584E00, 1415073280
        Winbond, 0x57454300, 1464156928
        Fuzhou Rockchip, 0x524F4343, 1380926275
        Google, 0x474F4F47, 1196379975
"@

        $manufacturerIDSet = ConvertFrom-Csv -InputObject $vendorList
        
        # $statusResult = New-Object -TypeName System.Collections.ArrayList
        $statusResult = @()
    }
    Process
    {
        foreach($computer in $ComputerName)
        {
            $computerStatus = New-Object -TypeName psobject -Property ([ordered]@{
                ComputerName    = [string]$computer
                TPMVendorID     = [int]$null
                TPMVendor       = [string]$null
                VendorVersion   = [string]$null
                SpecVer         = [string]$null
                Checked         = [bool]$False
                Error           = [bool]$False
            })
            
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
                $computerStatus.TPMVendorID = $tpmDetail.ManufacturerId
                $computerStatus.TPMVendor = $manufacturerIDSet.where({$_.TPMVendorIDDec -eq $computerStatus.TPMVendorID}).TPMVendor

                $computerStatus.VendorVersion = $tpmDetail.ManufacturerVersion
                $computerStatus.SpecVer = ($tpmDetail.SpecVersion).Split(',')[0]
                
                
                
            }
            # [void]$statusResult.Add($computerStatus)
            $statusResult += @($computerStatus)
        }
    }
    End
    {
        # $statusResult = $statusResult | Where-Object {$_ -notlike $null}
        $statusResult
    }
}