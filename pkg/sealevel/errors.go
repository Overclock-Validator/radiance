package sealevel

import "errors"

// instruction errors
var (
	InstrErrInvalidInstructionData      = errors.New("InstrErrInvalidInstructionData")
	InstrErrNotEnoughAccountKeys        = errors.New("InstrErrNotEnoughAccountKeys")
	InstrErrComputationalBudgetExceeded = errors.New("InstrErrComputationalBudgetExceeded")
	InstrErrMissingAccount              = errors.New("InstrErrMissingAccount")
	InstrErrInvalidAccountOwner         = errors.New("InstrErrInvalidAccountOwner")
	InstrErrInvalidAccountData          = errors.New("InstrErrInvalidAccountData")
	InstrErrMissingRequiredSignature    = errors.New("InstrErrMissingRequiredSignature")
	InstrErrInvalidArgument             = errors.New("InstrErrInvalidArgument")
	InstrErrExecutableDataModified      = errors.New("InstrErrExecutableDataModified")
	InstrErrReadonlyDataModified        = errors.New("InstrErrReadonlyDataModified")
	InstrErrExternalAccountDataModified = errors.New("InstrErrExternalAccountDataModified")
	InstrErrPrivilegeEscalation         = errors.New("InstrErrPrivilegeEscalation")
	InstrErrAccountNotExecutable        = errors.New("InstrErrAccountNotExecutable")
	InstrErrAccountDataSizeChanged      = errors.New("InstrErrAccountDataSizeChanged")
	InstrErrInvalidRealloc              = errors.New("InstrErrInvalidRealloc")
	InstrErrModifiedProgramId           = errors.New("InstrErrModifiedProgramId")
	InstrErrCallDepth                   = errors.New("InstrErrCallDepth")
	InstrErrUnsupportedProgramId        = errors.New("InstrErrUnsupportedProgramId")
	InstrErrReentrancyNotAllowed        = errors.New("InstrErrReentrancyNotAllowed")
	InstrErrArithmeticOverflow          = errors.New("InstrErrArithmeticOverflow")
	InstrErrUnbalancedInstruction       = errors.New("InstrErrUnbalancedInstruction")
	InstrErrAccountDataTooSmall         = errors.New("InstrErrAccountDataTooSmall")
	InstrErrAccountBorrowOutstanding    = errors.New("InstrErrAccountBorrowOutstanding")
	InstrErrExternalAccountLamportSpend = errors.New("InstrErrExternalAccountLamportSpend")
	InstrErrReadonlyLamportChange       = errors.New("InstrErrReadonlyLamportChange")
	InstrErrExecutableLamportChange     = errors.New("InstrErrExecutableLamportChange")
	InstrErrInsufficientFunds           = errors.New("InstrErrInsufficientFunds")
	InstrErrAccountAlreadyInitialized   = errors.New("InstrErrAccountAlreadyInitialized")
	InstrErrUninitializedAccount        = errors.New("InstrErrUninitializedAccount")
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

// precompile errors
var (
	PrecompileErrInvalidInstructionDataSize = errors.New("ErrInvalidInstructionDataSize")
)

// instruction errors - Solana numerical error codes
const (
	InstrErrCodeSuccess                     = 0
	InstrErrCodeInvalidArgument             = 2
	InstrErrCodeInvalidInstructionData      = 3
	InstrErrCodeInvalidAccountData          = 4
	InstrErrCodeMissingRequiredSignature    = 8
	InstrErrCodeExternalAccountDataModified = 14
	InstrErrCodeReadonlyDataModified        = 16
	InstrErrCodeNotEnoughAccountKeys        = 20
	InstrErrCodeExecutableDataModified      = 28
	InstrErrCodeMissingAccount              = 33
	InstrErrCodeComputationalBudgetExceeded = 38
	InstrErrCodeInvalidAccountOwner         = 47
)

// precompile program errors - Solana numerical error codes
const (
	PrecompileErrCodeInvalidDataOffsets         = 100
	PrecompileErrCodeInvalidInstructionDataSize = 101
	PrecompileErrCodeInvalidSignature           = 102
	PrecompileErrCodeInvalidRecoveryId          = 103 // TODO: not sure this is correct
)

// TODO: add additional error conversions
func translateErrToInstrErrCode(err error) int {
	var errorCode int
	switch err {
	case InstrErrInvalidInstructionData:
		errorCode = InstrErrCodeInvalidInstructionData
	case InstrErrNotEnoughAccountKeys:
		errorCode = InstrErrCodeNotEnoughAccountKeys
	case InstrErrComputationalBudgetExceeded:
		errorCode = InstrErrCodeComputationalBudgetExceeded
	case InstrErrMissingAccount:
		errorCode = InstrErrCodeMissingAccount
	case InstrErrInvalidAccountOwner:
		errorCode = InstrErrCodeInvalidAccountOwner
	case InstrErrInvalidAccountData:
		errorCode = InstrErrCodeInvalidAccountData
	case InstrErrMissingRequiredSignature:
		errorCode = InstrErrCodeMissingRequiredSignature
	case InstrErrInvalidArgument:
		errorCode = InstrErrCodeInvalidArgument
	case InstrErrExecutableDataModified:
		errorCode = InstrErrCodeExecutableDataModified
	case InstrErrReadonlyDataModified:
		errorCode = InstrErrCodeReadonlyDataModified
	case InstrErrExternalAccountDataModified:
		errorCode = InstrErrCodeExternalAccountDataModified
	}
	return errorCode
}
