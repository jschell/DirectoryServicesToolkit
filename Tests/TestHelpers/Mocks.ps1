# TestHelpers/Mocks.ps1
# Shared mock data and helper stubs used across unit test files.
# Dot-source this file in BeforeAll blocks:
#   . "$PSScriptRoot/../../TestHelpers/Mocks.ps1"

# ── Enumeration mocks ────────────────────────────────────────────────────────

$script:MockDomainObjects = @(
    [PSCustomObject]@{
        Name              = 'TestUser1'
        SamAccountName    = 'testuser1'
        DistinguishedName = 'CN=TestUser1,OU=Users,DC=contoso,DC=com'
        ObjectClass       = 'user'
    }
    [PSCustomObject]@{
        Name              = 'TestUser2'
        SamAccountName    = 'testuser2'
        DistinguishedName = 'CN=TestUser2,OU=Users,DC=contoso,DC=com'
        ObjectClass       = 'user'
    }
)

$script:MockComputerObjects = @(
    [PSCustomObject]@{
        Name              = 'WORKSTATION01'
        SamAccountName    = 'WORKSTATION01$'
        DistinguishedName = 'CN=WORKSTATION01,OU=Workstations,DC=contoso,DC=com'
        ObjectClass       = 'computer'
    }
    [PSCustomObject]@{
        Name              = 'SERVER01'
        SamAccountName    = 'SERVER01$'
        DistinguishedName = 'CN=SERVER01,OU=Servers,DC=contoso,DC=com'
        ObjectClass       = 'computer'
    }
)

# ── Security mocks ───────────────────────────────────────────────────────────

$script:MockKeyCredLinkObjects = @(
    [PSCustomObject]@{
        SamAccountName    = 'WORKSTATION01$'
        DistinguishedName = 'CN=WORKSTATION01,OU=Workstations,DC=contoso,DC=com'
        UserAccountControl = 4096
        MachineType       = 'Workstation'
    }
)

$script:MockBitlockerKeys = @(
    [PSCustomObject]@{
        DistinguishedName = 'CN={GUID},CN=WORKSTATION01,OU=Computers,DC=contoso,DC=com'
        RecoveryPassword  = '123456-234567-345678-456789-567890-678901-789012-890123'
    }
)

$script:MockDelegationObjects = @(
    [PSCustomObject]@{
        Name              = 'SVC-IIS'
        SamAccountName    = 'svc-iis'
        DistinguishedName = 'CN=svc-iis,OU=ServiceAccounts,DC=contoso,DC=com'
        DelegationType    = 'Unconstrained'
        SPNs              = @('HTTP/webserver.contoso.com')
    }
)

$script:MockKerberoastableAccounts = @(
    [PSCustomObject]@{
        SamAccountName    = 'svc-sql'
        DistinguishedName = 'CN=svc-sql,OU=ServiceAccounts,DC=contoso,DC=com'
        SPNs              = @('MSSQLSvc/sqlserver.contoso.com:1433')
        PasswordLastSet   = (Get-Date).AddDays(-180)
        Enabled           = $true
    }
)

$script:MockASREPRoastableAccounts = @(
    [PSCustomObject]@{
        SamAccountName     = 'legacyuser'
        DistinguishedName  = 'CN=legacyuser,OU=Users,DC=contoso,DC=com'
        UserAccountControl = 4194304
        Enabled            = $true
    }
)

# ── Account hygiene mocks ────────────────────────────────────────────────────

$script:MockStaleAccounts = @(
    [PSCustomObject]@{
        SamAccountName      = 'olduser'
        DistinguishedName   = 'CN=olduser,OU=Users,DC=contoso,DC=com'
        LastLogonTimestamp  = (Get-Date).AddDays(-120).ToFileTime()
        Enabled             = $true
    }
)

$script:MockPasswordPolicy = [PSCustomObject]@{
    Name                   = 'Default Domain Policy'
    MinPasswordLength      = 8
    PasswordHistoryCount   = 24
    MaxPasswordAge         = [timespan]::FromDays(90)
    MinPasswordAge         = [timespan]::FromDays(1)
    LockoutThreshold       = 5
    ComplexityEnabled      = $true
}

# ── Domain Controller mocks ───────────────────────────────────────────────────

$script:MockDomainControllers = @(
    [PSCustomObject]@{
        Name          = 'DC01.contoso.com'
        OSVersion     = 'Windows Server 2022 Standard'
        Site          = 'Default-First-Site-Name'
        IsGlobalCatalog = $true
    }
    [PSCustomObject]@{
        Name          = 'DC02.contoso.com'
        OSVersion     = 'Windows Server 2019 Standard'
        Site          = 'Default-First-Site-Name'
        IsGlobalCatalog = $false
    }
)

# ── Trust mocks ───────────────────────────────────────────────────────────────

$script:MockTrusts = @(
    [PSCustomObject]@{
        Name            = 'partner.com'
        TrustDirection  = 'Bidirectional'
        TrustType       = 'Forest'
        IsTransitive    = $true
        SIDFilteringEnabled = $true
    }
)

# ── AD CS / PKI mocks ────────────────────────────────────────────────────────

$script:MockADCSTemplates = @(
    [PSCustomObject]@{
        Name                    = 'VulnerableTemplate'
        DistinguishedName       = 'CN=VulnerableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
        ESCFlags                = @('ESC1', 'ESC3-Condition')
        IsVulnerable            = $true
        EnrolleeSuppliesSubject = $true
        AnyPurposeEKU           = $false
        NoRASignatureRequired   = $true
        NoManagerApproval       = $true
        EKUs                    = @('1.3.6.1.5.5.7.3.2')
        NameFlag                = 1
        EnrollmentFlag          = 0
        RASignatureCount        = 0
    }
    [PSCustomObject]@{
        Name                    = 'SafeTemplate'
        DistinguishedName       = 'CN=SafeTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
        ESCFlags                = @()
        IsVulnerable            = $false
        EnrolleeSuppliesSubject = $false
        AnyPurposeEKU           = $false
        NoRASignatureRequired   = $false
        NoManagerApproval       = $false
        EKUs                    = @('1.3.6.1.5.5.7.3.2')
        NameFlag                = 0
        EnrollmentFlag          = 2
        RASignatureCount        = 1
    }
)

$script:MockADCSAuthorities = @(
    [PSCustomObject]@{
        Name              = 'ContosoCA'
        DistinguishedName = 'CN=ContosoCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
        DNSHostName       = 'ca01.contoso.com'
        CAType            = 'EnterpriseRoot'
        CertificateExpiry = (Get-Date).AddYears(5)
        EnrollmentServers = @('http://ca01.contoso.com/certsrv', 'https://ca01.contoso.com/certsrv')
        HasWebEnrollment  = $true
        HTTPEndpoints     = @('http://ca01.contoso.com/certsrv')
        HTTPEndpointCount = 1
    }
)

# ── GPP Credential mocks ─────────────────────────────────────────────────────

$script:MockGPPCredentials = @(
    [PSCustomObject]@{
        GPOGuid           = '{12345678-1234-1234-1234-123456789012}'
        FilePath          = '\\contoso.com\SYSVOL\contoso.com\Policies\{12345678-1234-1234-1234-123456789012}\Machine\Preferences\Groups\Groups.xml'
        FileName          = 'Groups.xml'
        UserName          = 'Administrator'
        CPassword         = 'j1Uyj3Vx8TY9LtLZil2uAE0NnAAn9KZCP3T4bCVGdo='
        DecryptedPassword = 'P@ssw0rd123'
        IsDecrypted       = $true
        RiskLevel         = 'Critical'
        Finding           = 'cPassword credential found in GPP file'
    }
)

# ── DCSync mocks ─────────────────────────────────────────────────────────────

$script:MockDCSyncRights = @(
    [PSCustomObject]@{
        IdentityReference = 'CONTOSO\helpdesk-admin'
        Right             = 'DS-Replication-Get-Changes-All'
        RightGuid         = '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
        IsInherited       = $false
        IsCritical        = $true
        RiskLevel         = 'Critical'
        Finding           = 'Non-privileged principal holds DS-Replication-Get-Changes-All'
    }
)

# ── LAPS mocks ───────────────────────────────────────────────────────────────

$script:MockLAPSCoverage = @(
    [PSCustomObject]@{
        Name              = 'WORKSTATION01'
        SamAccountName    = 'WORKSTATION01$'
        DistinguishedName = 'CN=WORKSTATION01,OU=Workstations,DC=contoso,DC=com'
        OU                = 'OU=Workstations,DC=contoso,DC=com'
        LAPSVersion       = 'LegacyLAPS'
        HasLAPS           = $true
        IsExpired         = $false
        RiskLevel         = 'Low'
    }
    [PSCustomObject]@{
        Name              = 'UNMANAGED01'
        SamAccountName    = 'UNMANAGED01$'
        DistinguishedName = 'CN=UNMANAGED01,OU=Servers,DC=contoso,DC=com'
        OU                = 'OU=Servers,DC=contoso,DC=com'
        LAPSVersion       = 'None'
        HasLAPS           = $false
        IsExpired         = $false
        RiskLevel         = 'High'
    }
)

# ── LDAP security mocks ───────────────────────────────────────────────────────

$script:MockLDAPSigning = @(
    [PSCustomObject]@{
        DCName       = 'DC01.contoso.com'
        SigningValue = 2
        Description  = 'Require signing — LDAP signing enforced'
        RiskLevel    = 'Low'
        IsCompliant  = $true
        ErrorMessage = $null
    }
    [PSCustomObject]@{
        DCName       = 'DC02.contoso.com'
        SigningValue = 0
        Description  = 'No signing required — unsigned LDAP permitted'
        RiskLevel    = 'Critical'
        IsCompliant  = $false
        ErrorMessage = $null
    }
)

# ── NTLM policy mocks ─────────────────────────────────────────────────────────

$script:MockNTLMPolicy = @(
    [PSCustomObject]@{
        DCName                 = 'DC01.contoso.com'
        LmCompatibilityLevel   = 5
        LmCompatDescription    = 'Send NTLMv2 only — refuse LM and NTLMv1 everywhere'
        NoLMHash               = $true
        NtlmMinClientSec       = 537395200
        NtlmMinServerSec       = 537395200
        NTLMv2ClientRequired   = $true
        Encryption128BitClient = $true
        NTLMv2ServerRequired   = $true
        Encryption128BitServer = $true
        RiskLevel              = 'Low'
        IsCompliant            = $true
        ErrorMessage           = $null
    }
)

# ── Machine Account Quota mocks ───────────────────────────────────────────────

$script:MockMachineAccountQuota = [PSCustomObject]@{
    DomainName          = 'contoso.com'
    DomainDN            = 'DC=contoso,DC=com'
    MachineAccountQuota = 10
    RiskLevel           = 'High'
    Finding             = 'Any authenticated user can create up to 10 computer accounts — RBCD and coercion attack surface exposed'
    Remediation         = 'Set ms-DS-MachineAccountQuota to 0 on the domain NC root to prevent non-admin computer account creation'
}

# ── Protected Users mocks ─────────────────────────────────────────────────────

$script:MockProtectedUsersGaps = @(
    [PSCustomObject]@{
        SamAccountName             = 'da-jsmith'
        DistinguishedName          = 'CN=da-jsmith,OU=AdminAccounts,DC=contoso,DC=com'
        Enabled                    = $true
        PrivilegedGroup            = 'Domain Admins'
        InProtectedUsers           = $false
        HasSPN                     = $false
        HasUnconstrainedDelegation = $false
        IncompatibleSPN            = $false
        IncompatibleDelegation     = $false
        RiskLevel                  = 'High'
        Finding                    = "Privileged account 'da-jsmith' (Domain Admins) is not in Protected Users"
    }
)
