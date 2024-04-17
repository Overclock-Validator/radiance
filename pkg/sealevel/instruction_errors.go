package sealevel

import "errors"

// error values
var (

	// instruction errors
	ErrInvalidInstructionData      = errors.New("ErrInvalidInstructionData")
	ErrNotEnoughAccountKeys        = errors.New("ErrNotEnoughAccountKeys")
	ErrComputationalBudgetExceeded = errors.New("ErrComputationalBudgetExceeded")
	ErrMissingAccount              = errors.New("ErrMissingAccount")
	ErrInvalidAccountOwner         = errors.New("InvalidAccountOwner")
	ErrInvalidAccountData          = errors.New("ErrInvalidAccountData")
	ErrMissingRequiredSignature    = errors.New("ErrMissingRequiredSignature")
	ErrInvalidArgument             = errors.New("ErrInvalidArgument")
	ErrExecutableDataModified      = errors.New("ErrExecutableDataModified")
	ErrReadonlyDataModified        = errors.New("ErrReadonlyDataModified")
	ErrExternalAccountDataModified = errors.New("ErrExternalAccountDataModified")
	ErrPrivilegeEscalation         = errors.New("ErrPrivilegeEscalation")
	ErrAccountNotExecutable        = errors.New("ErrAccountNotExecutable")
	ErrAccountDataSizeChanged      = errors.New("ErrAccountDataSizeChanged")
	ErrInvalidRealloc              = errors.New("InvalidRealloc")
	ErrModifiedProgramId           = errors.New("ErrModifiedProgramId")
	ErrCallDepth                   = errors.New("ErrCallDepth")
	ErrUnsupportedProgramId        = errors.New("ErrUnsupportedProgramId")
	ErrReentrancyNotAllowed        = errors.New("ErrReentrancyNotAllowed")
	ErrArithmeticOverflow          = errors.New("ErrArithmeticOverflow")
	ErrUnbalancedInstruction       = errors.New("ErrUnbalancedInstruction")
	ErrAccountDataTooSmall         = errors.New("ErrAccountDataTooSmall")
	ErrAccountBorrowOutstanding    = errors.New("ErrAccountBorrowOutstanding")

	// precompile errors
	ErrInvalidInstructionDataSize = errors.New("ErrInvalidInstructionDataSize")
)

// Solana error codes for instruction errors
const (
	InstrSuccess                        = 0
	InstrErrInvalidArgument             = 2
	InstrErrInvalidInstructionData      = 3
	InstrErrInvalidAccountData          = 4
	InstrErrMissingRequiredSignature    = 8
	InstrErrExternalAccountDataModified = 14
	InstrErrReadonlyDataModified        = 16
	InstrErrNotEnoughAccountKeys        = 20
	InstrErrExecutableDataModified      = 28
	InstrErrMissingAccount              = 33
	InstrErrComputationalBudgetExceeded = 38
	InstrErrInvalidAccountOwner         = 47
)

// Solana error codes for precompile program errors
const (
	PrecompileErrInvalidDataOffsets         = 100
	PrecompileErrInvalidInstructionDataSize = 101
	PrecompileErrInvalidSignature           = 102
	PrecompileErrInvalidRecoveryId          = 103 // TODO: not sure this is correct
)

func translateErrToInstrErrCode(err error) int {
	var errorCode int
	switch err {
	case ErrInvalidInstructionData:
		errorCode = InstrErrInvalidInstructionData
	case ErrNotEnoughAccountKeys:
		errorCode = InstrErrNotEnoughAccountKeys
	case ErrComputationalBudgetExceeded:
		errorCode = InstrErrComputationalBudgetExceeded
	case ErrMissingAccount:
		errorCode = InstrErrMissingAccount
	case ErrInvalidAccountOwner:
		errorCode = InstrErrInvalidAccountOwner
	case ErrInvalidAccountData:
		errorCode = InstrErrInvalidAccountData
	case ErrMissingRequiredSignature:
		errorCode = InstrErrMissingRequiredSignature
	case ErrInvalidArgument:
		errorCode = InstrErrInvalidArgument
	case ErrExecutableDataModified:
		errorCode = InstrErrExecutableDataModified
	case ErrReadonlyDataModified:
		errorCode = InstrErrReadonlyDataModified
	case ErrExternalAccountDataModified:
		errorCode = InstrErrExternalAccountDataModified
	}
	return errorCode
}
