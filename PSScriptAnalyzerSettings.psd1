@{
    Rules = @{
        PSUseApprovedVerbs                                    = @{ Enable = $true }
        PSAvoidUsingWriteHost                                 = @{ Enable = $true }
        PSUseShouldProcessForStateChangingFunctions           = @{ Enable = $true }
        PSAvoidUsingInvokeExpression                          = @{ Enable = $true }
        PSUsePSCredentialType                                 = @{ Enable = $true }
        PSAvoidUsingPlainTextForPassword                      = @{ Enable = $true }
        PSAvoidUsingConvertToSecureStringWithPlainText        = @{ Enable = $true }
        PSUseOutputTypeCorrectly                              = @{ Enable = $true }
        PSUseCmdletCorrectly                                  = @{ Enable = $true }
    }
    ExcludeRules = @(
        # Allow positional parameters in short utility/pipeline scenarios
        'PSAvoidUsingPositionalParameters'

        # BOM is not required on Linux/cross-platform; files are UTF-8 without BOM
        'PSUseBOMForUnicodeEncodedFile'

        # Trailing whitespace cleanup is handled by editor tooling, not CI lint
        'PSAvoidTrailingWhitespace'

        # Plural nouns are intentional — these functions return collections
        'PSUseSingularNouns'
    )
}
