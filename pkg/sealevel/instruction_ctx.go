package sealevel

import (
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/safemath"
)

type InstructionCtx struct {
	programId           solana.PublicKey
	ProgramAccounts     []uint64
	InstructionAccounts []InstructionAccount
	Data                []byte
}

func (instrCtx *InstructionCtx) ProgramId() solana.PublicKey {
	return instrCtx.programId
}

func (instrCtx *InstructionCtx) IndexOfProgramAccountInTransaction(programAccountIndex uint64) (uint64, error) {
	if len(instrCtx.ProgramAccounts) == 0 || programAccountIndex > uint64(len(instrCtx.ProgramAccounts)-1) {
		return 0, NotEnoughAccountKeys
	}
	return instrCtx.ProgramAccounts[programAccountIndex], nil
}

func (instrCtx *InstructionCtx) NumberOfProgramAccounts() uint64 {
	return uint64(len(instrCtx.ProgramAccounts))
}

func (instrCtx *InstructionCtx) LastProgramKey(txCtx TransactionCtx) (solana.PublicKey, error) {
	programAccountIndex := safemath.SaturatingSubU64(instrCtx.NumberOfProgramAccounts(), 1)

	index, err := instrCtx.IndexOfProgramAccountInTransaction(programAccountIndex)
	if err != nil {
		return solana.PublicKey{}, err
	}

	return txCtx.KeyOfAccountAtIndex(index)
}

func (instrCtx *InstructionCtx) IndexOfInstructionAccountInTransaction(instrAcctIdx uint64) (uint64, error) {
	if len(instrCtx.InstructionAccounts) == 0 || instrAcctIdx > uint64(len(instrCtx.InstructionAccounts)-1) {
		return 0, NotEnoughAccountKeys
	}
	return instrCtx.InstructionAccounts[instrAcctIdx].IndexInTransaction, nil
}

func (instrCtx *InstructionCtx) BorrowAccount(txCtx TransactionCtx, idxInTx uint64, idxInInstr uint64) (*BorrowedAccount, error) {
	account, err := txCtx.Accounts.GetAccount(idxInTx)
	if err != nil {
		return nil, err
	}
	borrowedAcct := BorrowedAccount{Account: account, TxCtx: &txCtx, InstrCtx: instrCtx, IndexInTransaction: idxInTx, IndexInInstruction: idxInInstr}
	return &borrowedAcct, nil
}

func (instrCtx *InstructionCtx) BorrowInstructionAccount(txCtx TransactionCtx, instrAcctIdx uint64) (*BorrowedAccount, error) {
	idxInTx, err := instrCtx.IndexOfInstructionAccountInTransaction(instrAcctIdx)
	if err != nil {
		return nil, err
	}
	idxInInstr := safemath.SaturatingAddU64(instrCtx.NumberOfProgramAccounts(), instrAcctIdx)
	return instrCtx.BorrowAccount(txCtx, idxInTx, idxInInstr)
}

func (instrCtx *InstructionCtx) IsInstructionAccountSigner(instrAcctIdx uint64) (bool, error) {
	if len(instrCtx.InstructionAccounts) == 0 || instrAcctIdx > uint64(len(instrCtx.InstructionAccounts)) {
		return false, ErrMissingAccount
	}

	return instrCtx.InstructionAccounts[instrAcctIdx].IsSigner, nil
}

func (instrCtx *InstructionCtx) IsInstructionAccountWritable(instrAcctIdx uint64) (bool, error) {
	if len(instrCtx.InstructionAccounts) == 0 || instrAcctIdx > uint64(len(instrCtx.InstructionAccounts)) {
		return false, ErrMissingAccount
	}

	return instrCtx.InstructionAccounts[instrAcctIdx].IsWritable, nil
}
