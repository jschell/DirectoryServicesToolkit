function Unprotect-GPPPassword
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CPassword,

        [Parameter(Mandatory)]
        [byte[]]$Key
    )

    # Pad to required Base64 block length
    $mod     = $CPassword.Length % 4
    if ($mod -gt 0) { $CPassword += '=' * (4 - $mod) }

    $bytes   = [Convert]::FromBase64String($CPassword)

    $aes     = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.IV  = [byte[]]::new(16)
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    try
    {
        $decryptor = $aes.CreateDecryptor()
        $decrypted = $decryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
        [System.Text.Encoding]::Unicode.GetString($decrypted)
    }
    finally
    {
        $aes.Dispose()
    }
}

function Find-DSGPPCredential
{
    <#
    .SYNOPSIS
    Scans SYSVOL for Group Policy Preferences credential files containing encrypted passwords (cPassword).

    .DESCRIPTION
    Searches the domain SYSVOL share for Group Policy Preferences XML files that may contain
    encrypted credentials stored as cPassword attributes. These passwords are encrypted with a
    static AES-256 key published by Microsoft (MS14-025), making decryption trivial. The
    encrypted data persists indefinitely even after the MS14-025 patch, which only prevents new
    credentials from being stored. Requires read access to the domain SYSVOL share
    (\\domain\SYSVOL).

    .PARAMETER Domain
    DNS name of the target domain. Defaults to the current user's domain.

    .PARAMETER Redact
    When specified, suppresses plaintext password output while still flagging the presence of
    cPassword credentials.

    .EXAMPLE
    Find-DSGPPCredential -Domain 'contoso.com'

    Scans the SYSVOL of contoso.com for GPP credential files and returns decrypted passwords.

    .EXAMPLE
    Find-DSGPPCredential -Domain 'contoso.com' -Redact

    Scans SYSVOL and reports findings without exposing decrypted credential values in output.

    .NOTES
    #### Name:    Find-DSGPPCredential
    #### Author:  J Schell
    #### Version: 0.1.0
    #### License: MIT License

    Changelog:
    2026-03-04::0.1.0
    - Initial creation
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(HelpMessage = 'DNS name of the target domain')]
        [ValidateNotNullOrEmpty()]
        [string]$Domain = $env:USERDNSDOMAIN,

        [Parameter(HelpMessage = 'Suppress plaintext credential output')]
        [switch]$Redact
    )

    Begin
    {
        # AES-256 key published by Microsoft (MS14-025)
        $aesKey = [byte[]]@(
            0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,
            0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
            0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,
            0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b
        )

        $gppFiles = @(
            'Groups.xml'
            'Services.xml'
            'ScheduledTasks.xml'
            'DataSources.xml'
            'Printers.xml'
            'Drives.xml'
        )

        $sysvolPath = "\\$Domain\SYSVOL\$Domain\Policies"
        Write-Verbose "Scanning SYSVOL: $sysvolPath"

        $results = New-Object System.Collections.ArrayList
    }

    Process
    {
        try
        {
            $allFiles = Get-ChildItem -Path $sysvolPath -Recurse -Include $gppFiles -ErrorAction Stop
        }
        catch
        {
            Write-Error "Cannot access SYSVOL at '$sysvolPath': $_"
            return
        }

        foreach ($file in $allFiles)
        {
            Write-Verbose "Examining: $($file.FullName)"

            try
            {
                [xml]$xmlContent = Get-Content -Path $file.FullName -ErrorAction Stop
            }
            catch
            {
                Write-Verbose "Could not parse XML: $($file.FullName) — $_"
                continue
            }

            $cpasswordNodes = $xmlContent.SelectNodes('//*[@cpassword]')

            foreach ($node in $cpasswordNodes)
            {
                $cpassword = $node.GetAttribute('cpassword')
                if ([string]::IsNullOrEmpty($cpassword)) { continue }

                $userName = $node.GetAttribute('userName')
                if ([string]::IsNullOrEmpty($userName)) { $userName = $node.GetAttribute('name') }

                # Extract GPO GUID from path
                $gpoGuid = $null
                if ($file.FullName -match '\{([0-9A-Fa-f-]{36})\}')
                {
                    $gpoGuid = $Matches[1]
                }

                # Decrypt the cPassword
                $decryptedPassword = $null
                try
                {
                    $decryptedPassword = Unprotect-GPPPassword -CPassword $cpassword -Key $aesKey
                }
                catch
                {
                    Write-Verbose "Could not decrypt cpassword in '$($file.FullName)': $_"
                }

                [void]$results.Add(
                    [PSCustomObject]@{
                        GPOGuid           = $gpoGuid
                        FilePath          = $file.FullName
                        FileName          = $file.Name
                        UserName          = $userName
                        CPassword         = $cpassword
                        DecryptedPassword = if ($Redact) { '<REDACTED>' } else { $decryptedPassword }
                        IsDecrypted       = ($null -ne $decryptedPassword)
                        RiskLevel         = 'Critical'
                        Finding           = "cPassword credential found in GPP file '$($file.Name)' — GPO: $gpoGuid"
                    }
                )
            }
        }
    }

    End
    {
        $results.ToArray()
    }
}
