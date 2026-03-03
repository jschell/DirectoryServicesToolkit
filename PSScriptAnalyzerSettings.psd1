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
    )
}
