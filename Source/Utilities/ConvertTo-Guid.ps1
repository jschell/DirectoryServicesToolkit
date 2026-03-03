function ConvertTo-Guid
{
<#
.SYNOPSIS
Create GUID value from string input.

.DESCRIPTION
Used to generate unique per-string GUIDs, specifically to create matching GUIDs
for DSC node enrollment (based on known values for machine name, used as the
string input). The input string is converted to uppercase, rendered as an ASCII
byte array, and hashed with MD5. The resulting hash is returned as a GUID.

MD5 is used because the generated value must be exactly 32 hex characters.

.PARAMETER String
The value to convert to a GUID.

.EXAMPLE
ConvertTo-Guid -String MyTestValue

ced726f0-6132-63e6-3cf4-99cd854918e8

Description
-----------
The string 'MyTestValue' is converted to uppercase, rendered as a byte
array of ASCII characters, and hashed with the MD5 provider. The resulting
hash value is converted to a GUID representation and returned.

.EXAMPLE
'node01','node02' | ConvertTo-Guid

Converts multiple machine names to deterministic GUIDs via pipeline input.

.NOTES
#### Name:    ConvertTo-Guid
#### Author:  J Schell
#### Version: 0.1.0
#### License: MIT License

Changelog:
2017-11-15::0.1.0
- Initial creation

.LINK
https://gist.github.com/jschell/4b783d6ebeeeb17da26d29e9b3292075
#>

    [OutputType([guid])]
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $True)]
        [ValidateNotNullOrEmpty()]
        [string]
        $String
    )

    Begin {}

    Process
    {
        $hashProvider = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
        $targetForHash = [System.Text.Encoding]::ASCII.GetBytes($String.ToUpper())
        $hashBytes = $hashProvider.ComputeHash($targetForHash)

        # format each byte as 2 char hex - 0-255::00-FF
        $hexString = $null
        foreach($byte in $hashBytes)
        {
            $hexString += "{0:X2}" -f $byte
        }

        [guid]$generatedGuid = $hexString

        return $generatedGuid.Guid
    }

    End {}
}
