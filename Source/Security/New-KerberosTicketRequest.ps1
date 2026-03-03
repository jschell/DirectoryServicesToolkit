function New-KerberosTicketRequest
{
<#

.NOTES

#### Name:     New-KerberosTicketRequest
#### Author:   J Schell
#### Version:  0.1.0
#### License:  MIT License

### Change Log

##### 2018-07-06::0.1.0
-initial creation

#>    


    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        [string]
        $Server,

        [string]
        $SPN = 'host'
    )

    $target = "$($SPN)/$($Server)"

    if ($PSCmdlet.ShouldProcess($target, 'Request Kerberos service ticket'))
    {
        Try
        {
            $ticket = [System.IdentityModel.Tokens.KerberosRequestorSecurityToken]::new($target)
        }
        Catch
        {
            if( $($Error.Exception.InnerException.InnerException.InnerException) -like "*The specified target is unknown or unreachable")
            {
                Write-Error "The specified target is unknown or unreachable"
            }
            else
            {
                Write-Error $_
            }
        }
        $ticket
    }
}