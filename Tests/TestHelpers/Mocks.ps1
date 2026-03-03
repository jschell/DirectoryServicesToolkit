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
