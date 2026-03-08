# DirectoryServicesToolkit.psd1
# Module manifest — canonical version source.
# ModuleVersion is the authoritative version for releases and git tags.
# FunctionsToExport is kept current by `Invoke-Build Build`.

@{
    ModuleVersion = '0.4.0'
    GUID              = 'c4a3b2d1-e5f6-4789-a0bc-1d2e3f4a5b6c'
    Author            = 'J Schell'
    Description       = 'Active Directory security assessment and operational toolkit'
    PowerShellVersion = '7.0'
    RootModule        = 'DirectoryServicesToolkit.psm1'

    FunctionsToExport = @(
        # Enumeration
        'Find-DSRODCCachedCredentials'
        'Find-DSUserCreatedComputers'
        'Get-DSAdminAccounts'
        'Get-DSAdminSDHolder'
        'Get-DSComputerByProperty'
        'Get-DSDomainObjects'
        'Get-DSGPO'
        'Get-DSKeyCredLink'
        'Get-DSMachineAccountQuota'
        'Get-DSRODCConfig'
        'Get-DSSelectiveAuth'
        'Get-DSServiceAccounts'
        'Get-DSUserByProperty'

        # Security
        'ConvertFrom-TrustAttributeValue'
        'Find-DSADCSEnrollmentAgents'
        'Find-DSADCSTemplate'
        'Find-DSADCSTemplateACL'
        'Find-DSADCSWebEnrollment'
        'Find-DSASREPRoastable'
        'Find-DSBitlockerKey'
        'Find-DSDCSyncRights'
        'Find-DSDelegation'
        'Find-DSGPPCredential'
        'Find-DSInterestingACE'
        'Find-DSKerberoastable'
        'Get-DSADCSAuthority'
        'Get-DSLAPSCoverage'
        'New-KerberosTicketRequest'
        'Test-DSADCSACL'
        'Test-DSADCSCAFlags'
        'Test-DSLAPSPermissions'
        'Test-IfxTPM'

        # AccountHygiene
        'Find-DSPasswordNeverExpires'
        'Find-DSPasswordNotRequired'
        'Find-DSStaleAccounts'
        'Find-DSStalePrivilegedAccounts'
        'Find-DSWeakEncryptionAccounts'
        'Get-DSPasswordPolicy'
        'Get-DSProtectedUsersGaps'
        'Get-LastLoginInDomain'

        # Trusts
        'Get-DSTrustRelationship'
        'Test-DSTrustSIDFiltering'

        # DomainControllers
        'Find-DSCoercionSurface'
        'Find-DSNTLMRestrictions'
        'Get-DSNTLMPolicy'
        'Get-DSReplicationStatus'
        'Get-DSResponseTime'
        'Get-DSSysvolHealth'
        'Get-OSLevelDomainController'
        'Test-DSLDAPChannelBinding'
        'Test-DSLDAPSecurity'
        'Test-DSLDAPSigning'
        'Test-DSPrintSpooler'
        'Test-DSSMBSigning'

        # DNS
        'Find-DSADIDNSRecord'
        'Find-StaleDNSDomainRecord'
        'Test-DSDNSSecurity'

        # Reporting
        'Compare-DSBaseline'
        'Invoke-DSBaselineCapture'
        'New-DSAssessmentReport'

        # Utilities
        'ConvertTo-Guid'
        'Get-TPMDetail'
    )

    PrivateData = @{
        PSData = @{
            Tags       = @('ActiveDirectory', 'Security', 'Audit', 'DirectoryServices')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/jschell/DirectoryServicesToolkit'
        }
    }
}
