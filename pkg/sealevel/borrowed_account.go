package sealevel

import (
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/safemath"
)

type BorrowedAccount struct {
	TxCtx              *TransactionCtx
	InstrCtx           *InstructionCtx
	IndexInTransaction uint64
	IndexInInstruction uint64
	Account            *accounts.Account
}

func (acct *BorrowedAccount) Owner() solana.PublicKey {
	return acct.Account.Owner
}

func (acct *BorrowedAccount) Touch() error {
	err := acct.TxCtx.Accounts.Touch(acct.IndexInTransaction)
	if err != nil {
		return err
	}
	return nil
}

func (acct *BorrowedAccount) Data() []byte {
	return acct.Account.Data
}

func (acct *BorrowedAccount) SetData(features features.Features, data []byte) error {
	err := acct.DataCanBeChanged(features)
	if err != nil {
		return err
	}
	err = acct.Touch()
	if err != nil {
		return err
	}

	acct.Account.SetData(data)
	return nil
}

func (acct *BorrowedAccount) IsSigner() bool {
	instrCtx := acct.InstrCtx
	if acct.IndexInInstruction < instrCtx.NumberOfProgramAccounts() {
		return false
	}

	instrAcctIdx := safemath.SaturatingSubU64(acct.IndexInInstruction, instrCtx.NumberOfProgramAccounts())
	isSigner, err := instrCtx.IsInstructionAccountSigner(instrAcctIdx)
	if err != nil {
		return false
	}
	return isSigner
}

func (acct *BorrowedAccount) Key() solana.PublicKey {
	key, err := acct.TxCtx.KeyOfAccountAtIndex(acct.IndexInTransaction)
	if err != nil {
		panic("supposedly impossible failure")
	}
	return key
}

func (acct *BorrowedAccount) IsExecutable(features features.Features) bool {
	return acct.Account.IsBuiltin() || acct.Account.IsExecutable(features)
}

func (acct *BorrowedAccount) IsWritable() bool {
	instrCtx := acct.InstrCtx
	if acct.IndexInInstruction < instrCtx.NumberOfProgramAccounts() {
		return false
	}

	instrAcctIdx := safemath.SaturatingSubU64(acct.IndexInInstruction, instrCtx.NumberOfProgramAccounts())
	writable, err := instrCtx.IsInstructionAccountWritable(instrAcctIdx)
	if err != nil {
		return false
	}

	return writable
}

func (acct *BorrowedAccount) IsOwnedByCurrentProgram() bool {
	lastProgramKey, err := acct.InstrCtx.LastProgramKey(*acct.TxCtx)
	if err != nil {
		return false
	}
	return lastProgramKey == acct.Owner()
}

func (acct *BorrowedAccount) DataCanBeChanged(features features.Features) error {
	if acct.IsExecutable(features) {
		return ErrExecutableDataModified
	}
	if !acct.IsWritable() {
		return ErrReadonlyDataModified
	}
	if !acct.IsOwnedByCurrentProgram() {
		return ErrExternalAccountDataModified
	}
	return nil
}
