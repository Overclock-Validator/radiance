package sealevel

import "errors"

// error values
var (
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
)

// Solana error codes
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
