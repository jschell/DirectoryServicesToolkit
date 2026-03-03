function ConvertFrom-TrustAttributeValue {
<#
.SYNOPSIS
Converts a Trust Attribute int value to human readable form.

.PARAMETER Value
The int Trust Attribute value to convert.

.PARAMETER ShowAll
Show all Trust Attribute values, with a + indicating the value is currently set.

.EXAMPLE
PS C:\> ConvertFrom-TrustAttributeValue -Value 1112

Convert the UAC value 1112 to human readable format.

.NOTES

#### Name:      ConvertFrom-TrustAttributeValue
#### Author:    J Schell
#### Version:   0.1.0
#### License:   MIT License

### ChangeLog

##### 2018-12-04::0.1.0
- initial creation
- repurposed ConvertFrom-UACValue function
#>


    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$True,
            ValueFromPipeline=$True)]
        $Value,

        [Switch]
        $ShowAll
    )

    Begin
    {
        # values from https://msdn.microsoft.com/en-us/library/cc223779.aspx
        $TrustAttrValues = New-Object System.Collections.Specialized.OrderedDictionary

        $TrustAttrValues.Add("TRUST_ATTRIBUTE_NON_TRANSITIVE",                           1)
        $TrustAttrValues.Add("TRUST_ATTRIBUTE_UPLEVEL_ONLY",                             2)
        $TrustAttrValues.Add("TRUST_ATTRIBUTE_QUARANTINED_DOMAIN",                       4)
        $TrustAttrValues.Add("TRUST_ATTRIBUTE_FOREST_TRANSITIVE",                        8)
        $TrustAttrValues.Add("TRUST_ATTRIBUTE_CROSS_ORGANIZATION",                      16)
        $TrustAttrValues.Add("TRUST_ATTRIBUTE_WITHIN_FOREST",                           32)
        $TrustAttrValues.Add("TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL",                       64)
        $TrustAttrValues.Add("TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION",                    128)
        $TrustAttrValues.Add("TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION",   512)
        $TrustAttrValues.Add("TRUST_ATTRIBUTE_PIM_TRUST",                             1024)
    }
    Process
    {
        $ResultTrustAttrValues = New-Object System.Collections.Specialized.OrderedDictionary

        if($Value -is [Int])
        {
            $IntValue = $Value
        }
        elseif ($Value -is [PSCustomObject])
        {
            if($Value.trustattributes)
            {
                $IntValue = $Value.trustattributes
            }
        }
        else
        {
            Write-Warning "Invalid object input for -Value : $Value"
            return $Null
        }

        if( $ShowAll )
        {
            foreach ($TrustAttrValue in $TrustAttrValues.GetEnumerator())
            {
                if( ($IntValue -band $TrustAttrValue.Value) -eq $TrustAttrValue.Value)
                {
                    $ResultTrustAttrValues.Add($TrustAttrValue.Name, "$($TrustAttrValue.Value)+")
                }
                else
                {
                    $ResultTrustAttrValues.Add($TrustAttrValue.Name, "$($TrustAttrValue.Value)")
                }
            }
        }
        else
        {
            foreach ($TrustAttrValue in $TrustAttrValues.GetEnumerator())
            {
                if( ($IntValue -band $TrustAttrValue.Value) -eq $TrustAttrValue.Value)
                {
                    $ResultTrustAttrValues.Add($TrustAttrValue.Name, "$($TrustAttrValue.Value)")
                }
            }
        }
        $ResultTrustAttrValues
    }
}
