package sealevel

import "errors"

// instruction errors
var (
	InstrErrInvalidInstructionData                 = errors.New("InstrErrInvalidInstructionData")
	InstrErrNotEnoughAccountKeys                   = errors.New("InstrErrNotEnoughAccountKeys")
	InstrErrComputationalBudgetExceeded            = errors.New("InstrErrComputationalBudgetExceeded")
	InstrErrMissingAccount                         = errors.New("InstrErrMissingAccount")
	InstrErrInvalidAccountOwner                    = errors.New("InstrErrInvalidAccountOwner")
	InstrErrInvalidAccountData                     = errors.New("InstrErrInvalidAccountData")
	InstrErrMissingRequiredSignature               = errors.New("InstrErrMissingRequiredSignature")
	InstrErrInvalidArgument                        = errors.New("InstrErrInvalidArgument")
	InstrErrExecutableDataModified                 = errors.New("InstrErrExecutableDataModified")
	InstrErrReadonlyDataModified                   = errors.New("InstrErrReadonlyDataModified")
	InstrErrExternalAccountDataModified            = errors.New("InstrErrExternalAccountDataModified")
	InstrErrPrivilegeEscalation                    = errors.New("InstrErrPrivilegeEscalation")
	InstrErrAccountNotExecutable                   = errors.New("InstrErrAccountNotExecutable")
	InstrErrAccountDataSizeChanged                 = errors.New("InstrErrAccountDataSizeChanged")
	InstrErrInvalidRealloc                         = errors.New("InstrErrInvalidRealloc")
	InstrErrModifiedProgramId                      = errors.New("InstrErrModifiedProgramId")
	InstrErrCallDepth                              = errors.New("InstrErrCallDepth")
	InstrErrUnsupportedProgramId                   = errors.New("InstrErrUnsupportedProgramId")
	InstrErrReentrancyNotAllowed                   = errors.New("InstrErrReentrancyNotAllowed")
	InstrErrArithmeticOverflow                     = errors.New("InstrErrArithmeticOverflow")
	InstrErrUnbalancedInstruction                  = errors.New("InstrErrUnbalancedInstruction")
	InstrErrAccountDataTooSmall                    = errors.New("InstrErrAccountDataTooSmall")
	InstrErrAccountBorrowOutstanding               = errors.New("InstrErrAccountBorrowOutstanding")
	InstrErrExternalAccountLamportSpend            = errors.New("InstrErrExternalAccountLamportSpend")
	InstrErrReadonlyLamportChange                  = errors.New("InstrErrReadonlyLamportChange")
	InstrErrExecutableLamportChange                = errors.New("InstrErrExecutableLamportChange")
	InstrErrInsufficientFunds                      = errors.New("InstrErrInsufficientFunds")
	InstrErrAccountAlreadyInitialized              = errors.New("InstrErrAccountAlreadyInitialized")
	InstrErrUninitializedAccount                   = errors.New("InstrErrUninitializedAccount")
	InstrErrIncorrectProgramId                     = errors.New("InstrErrIncorrectProgramId")
	InstrErrImmutable                              = errors.New("InstrErrImmutable")
	InstrErrIncorrectAuthority                     = errors.New("InstrErrIncorrectAuthority")
	InstrErrExecutableAccountNotRentExempt         = errors.New("InstrErrExecutableAccountNotRentExempt")
	InstrErrExecutableModified                     = errors.New("InstrErrExecutableModified")
	InstrErrMaxAccountsExceeded                    = errors.New("InstrErrMaxAccountsExceeded")
	InstrErrAccountBorrowFailed                    = errors.New("InstrErrAccountBorrowFailed")
	InstrErrDuplicateAccountIndex                  = errors.New("InstrErrDuplicateAccountIndex")
	InstrErrRentEpochModified                      = errors.New("InstrErrRentEpochModified")
	InstrErrDuplicateAccountOutOfSync              = errors.New("InstrErrDuplicateAccountOutOfSync")
	InstrErrCustom                                 = errors.New("InstrErrCustom")
	InstrErrInvalidError                           = errors.New("InstrErrInvalidError")
	InstrErrGenericError                           = errors.New("InstrErrGenericError")
	InstrErrMaxSeedLengthExceeded                  = errors.New("InstrErrMaxSeedLengthExceeded")
	InstrErrInvalidSeeds                           = errors.New("InstrErrInvalidSeeds")
	InstrErrProgramEnvironmentSetupFailure         = errors.New("InstrErrProgramEnvironmentSetupFailure")
	InstrErrProgramFailedToComplete                = errors.New("InstrErrProgramFailedToComplete")
	InstrErrProgramFailedToCompile                 = errors.New("InstrErrProgramFailedToCompile")
	InstrErrBorshIoError                           = errors.New("InstrErrBorshIoError")
	InstrErrAccountNotRentExempt                   = errors.New("InstrErrAccountNotRentExempt")
	InstrErrUnsupportedSysvar                      = errors.New("InstrErrUnsupportedSysvar")
	InstrErrIllegalOwner                           = errors.New("InstrErrIllegalOwner")
	InstrErrMaxAccountsDataAllocationsExceeded     = errors.New("InstrErrMaxAccountsDataAllocationsExceeded")
	InstrErrMaxInstructionTraceLengthExceeded      = errors.New("InstrErrMaxInstructionTraceLengthExceeded")
	InstrErrBuiltinProgramsMustConsumeComputeUnits = errors.New("InstrErrBuiltinProgramsMustConsumeComputeUnits")
)

// syscall errors
var (
	SyscallErrCopyOverlapping                    = errors.New("SyscallErrCopyOverlapping")
	SyscallErrTooManySlices                      = errors.New("SyscallErrTooManySlices")
	SyscallErrInvalidLength                      = errors.New("SyscallErrInvalidLength")
	SyscallErrInvalidString                      = errors.New("SyscallErrInvalidString")
	SyscallErrMaxSeedLengthExceeded              = errors.New("SyscallErrMaxSeedLengthExceeded")
	SyscallErrReturnDataTooLarge                 = errors.New("SyscallErrReturnDataTooLarge")
	SyscallErrInvalidArgument                    = errors.New("SyscallErrInvalidArgument")
	SyscallErrNotEnoughAccountKeys               = errors.New("SyscallErrNotEnoughAccountKeys")
	SyscallErrTooManySigners                     = errors.New("SyscallErrTooManySigners")
	SyscallErrTooManyBytesConsumed               = errors.New("SyscallErrTooManyBytesConsumed")
	SyscallErrMalformedBool                      = errors.New("SyscallErrMalformedBool")
	SyscallErrProgramNotSupported                = errors.New("SyscallErrProgramNotSupported")
	SyscallErrMaxInstructionDataLenExceeded      = errors.New("SyscallErrMaxInstructionDataLenExceeded")
	SyscallErrMaxInstructionAccountsExceeded     = errors.New("SyscallErrMaxInstructionAccountsExceeded")
	SyscallErrInstructionTooLarge                = errors.New("SyscallErrInstructionTooLarge")
	SyscallErrMaxInstructionAccountInfosExceeded = errors.New("SyscallErrMaxInstructionAccountInfosExceeded")
	SyscallErrTooManyAccounts                    = errors.New("SyscallErrTooManyAccounts")
)

var (
	PubkeyErrIllegalOwner          = errors.New("PubkeyErrIllegalOwner")
	PubkeyErrMaxSeedLengthExceeded = errors.New("PubkeyErrMaxSeedLengthExceeded")
)

// precompile errors
var (
	PrecompileErrInvalidInstructionDataSize = errors.New("ErrInvalidInstructionDataSize")
)

// instruction errors - Solana numerical error codes
const (
	InstrErrCodeSuccess                                = 0
	InstrErrCodeGenericError                           = 0
	InstrErrCodeInvalidArgument                        = 1
	InstrErrCodeInvalidInstructionData                 = 2
	InstrErrCodeInvalidAccountData                     = 3
	InstrErrCodeAccountDataTooSmall                    = 4
	InstrErrCodeInsufficientFunds                      = 5
	InstrErrCodeIncorrectProgramId                     = 6
	InstrErrCodeMissingRequiredSignature               = 7
	InstrErrCodeAccountAlreadyInitialized              = 8
	InstrErrCodeUninitializedAccount                   = 9
	InstrErrCodeUnbalancedInstruction                  = 10
	InstrErrCodeModifiedProgramId                      = 11
	InstrErrCodeExternalAccountLamportSpend            = 12
	InstrErrCodeExternalAccountDataModified            = 13
	InstrErrCodeReadonlyLamportChange                  = 14
	InstrErrCodeReadonlyDataModified                   = 15
	InstrErrCodeDuplicateAccountIndex                  = 16
	InstrErrCodeExecutableModified                     = 17
	InstrErrCodeRentEpochModified                      = 18
	InstrErrCodeNotEnoughAccountKeys                   = 19
	InstrErrCodeAccountDataSizeChanged                 = 20
	InstrErrCodeAccountNotExecutable                   = 21
	InstrErrCodeAccountBorrowFailed                    = 22
	InstrErrCodeAccountBorrowOutstanding               = 23
	InstrErrCodeDuplicateAccountOutOfSync              = 24
	InstrErrCodeCustom                                 = 25
	InstrErrCodeInvalidError                           = 26
	InstrErrCodeExecutableDataModified                 = 27
	InstrErrCodeExecutableLamportChange                = 28
	InstrErrCodeExecutableAccountNotRentExempt         = 29
	InstrErrCodeUnsupportedProgramId                   = 30
	InstrErrCodeCallDepth                              = 31
	InstrErrCodeMissingAccount                         = 32
	InstrErrCodeReentrancyNotAllowed                   = 33
	InstrErrCodeMaxSeedLengthExceeded                  = 34
	InstrErrCodeInvalidSeeds                           = 35
	InstrErrCodeInvalidRealloc                         = 36
	InstrErrCodeComputationalBudgetExceeded            = 37
	InstrErrCodePrivilegeEscalation                    = 38
	InstrErrCodeProgramEnvironmentSetupFailure         = 39
	InstrErrCodeProgramFailedToComplete                = 40
	InstrErrCodeProgramFailedToCompile                 = 41
	InstrErrCodeImmutable                              = 42
	InstrErrCodeIncorrectAuthority                     = 43
	InstrErrCodeBorshIoError                           = 44
	InstrErrCodeAccountNotRentExempt                   = 45
	InstrErrCodeInvalidAccountOwner                    = 46
	InstrErrCodeArithmeticOverflow                     = 47
	InstrErrCodeUnsupportedSysvar                      = 48
	InstrErrCodeIllegalOwner                           = 49
	InstrErrCodeMaxAccountsDataAllocationsExceeded     = 50
	InstrErrCodeMaxAccountsExceeded                    = 51
	InstrErrCodeMaxInstructionTraceLengthExceeded      = 52
	InstrErrCodeBuiltinProgramsMustConsumeComputeUnits = 53
)

// precompile program errors - Solana numerical error codes
const (
	PrecompileErrCodeInvalidDataOffsets         = 100
	PrecompileErrCodeInvalidInstructionDataSize = 101
	PrecompileErrCodeInvalidSignature           = 102
	PrecompileErrCodeInvalidRecoveryId          = 103 // TODO: not sure this is correct
)

var solanaNumericalErrCodes = map[error]int{
	/* instruction errors */
	InstrErrGenericError:                           0,
	InstrErrInvalidArgument:                        1,
	InstrErrInvalidInstructionData:                 2,
	InstrErrInvalidAccountData:                     3,
	InstrErrAccountDataTooSmall:                    4,
	InstrErrInsufficientFunds:                      5,
	InstrErrIncorrectProgramId:                     6,
	InstrErrMissingRequiredSignature:               7,
	InstrErrAccountAlreadyInitialized:              8,
	InstrErrUninitializedAccount:                   9,
	InstrErrUnbalancedInstruction:                  10,
	InstrErrModifiedProgramId:                      11,
	InstrErrExternalAccountLamportSpend:            12,
	InstrErrExternalAccountDataModified:            13,
	InstrErrReadonlyLamportChange:                  14,
	InstrErrReadonlyDataModified:                   15,
	InstrErrDuplicateAccountIndex:                  16,
	InstrErrExecutableModified:                     17,
	InstrErrRentEpochModified:                      18,
	InstrErrNotEnoughAccountKeys:                   19,
	InstrErrAccountDataSizeChanged:                 20,
	InstrErrAccountNotExecutable:                   21,
	InstrErrAccountBorrowFailed:                    22,
	InstrErrAccountBorrowOutstanding:               23,
	InstrErrDuplicateAccountOutOfSync:              24,
	InstrErrCustom:                                 25,
	InstrErrInvalidError:                           26,
	InstrErrExecutableDataModified:                 27,
	InstrErrExecutableLamportChange:                28,
	InstrErrExecutableAccountNotRentExempt:         29,
	InstrErrUnsupportedProgramId:                   30,
	InstrErrCallDepth:                              31,
	InstrErrMissingAccount:                         32,
	InstrErrReentrancyNotAllowed:                   33,
	InstrErrMaxSeedLengthExceeded:                  34,
	InstrErrInvalidSeeds:                           35,
	InstrErrInvalidRealloc:                         36,
	InstrErrComputationalBudgetExceeded:            37,
	InstrErrPrivilegeEscalation:                    38,
	InstrErrProgramEnvironmentSetupFailure:         39,
	InstrErrProgramFailedToComplete:                40,
	InstrErrProgramFailedToCompile:                 41,
	InstrErrImmutable:                              42,
	InstrErrIncorrectAuthority:                     43,
	InstrErrBorshIoError:                           44,
	InstrErrAccountNotRentExempt:                   45,
	InstrErrInvalidAccountOwner:                    46,
	InstrErrArithmeticOverflow:                     47,
	InstrErrUnsupportedSysvar:                      48,
	InstrErrIllegalOwner:                           49,
	InstrErrMaxAccountsDataAllocationsExceeded:     50,
	InstrErrMaxAccountsExceeded:                    51,
	InstrErrMaxInstructionTraceLengthExceeded:      52,
	InstrErrBuiltinProgramsMustConsumeComputeUnits: 53,

	/* system program errors */
	SystemProgErrAccountAlreadyInUse:        0,
	SystemProgErrResultWithNegativeLamports: 1,
	SystemProgErrInvalidAccountDataLength:   3,
	SystemProgErrAddressWithSeedMismatch:    5,
	SystemProgErrNonceNoRecentBlockhashes:   6,
	SystemProgErrNonceBlockhashNotExpired:   7,

	/* pubkey errors */
	PubkeyErrMaxSeedLengthExceeded: 0,
	PubkeyErrIllegalOwner:          2,
}

var customErrs = map[error]bool{
	SystemProgErrAccountAlreadyInUse:        true,
	SystemProgErrResultWithNegativeLamports: true,
	SystemProgErrInvalidAccountDataLength:   true,
	SystemProgErrAddressWithSeedMismatch:    true,
	SystemProgErrNonceNoRecentBlockhashes:   true,
	SystemProgErrNonceBlockhashNotExpired:   true,
	PubkeyErrMaxSeedLengthExceeded:          true,
	PubkeyErrIllegalOwner:                   true,
}

func IsCustomErr(err error) bool {
	return customErrs[err]
}

// TODO: add additional error conversions
func TranslateErrToErrCode(err error) int {
	if err == nil {
		return InstrErrCodeSuccess
	}

	return solanaNumericalErrCodes[err]
}
