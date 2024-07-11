package sealevel

import (
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/ryanavella/wide"
	"go.firedancer.io/radiance/pkg/safemath"
)

type InstructionCtx struct {
	programId                     solana.PublicKey
	ProgramAccounts               []uint64
	InstructionAccounts           []InstructionAccount
	Data                          []byte
	InstructionAccountsLamportSum wide.Uint128
	NestingLevel                  uint64
}

func (instrCtx *InstructionCtx) ProgramId() solana.PublicKey {
	return instrCtx.programId
}

func (instrCtx *InstructionCtx) IndexOfProgramAccountInTransaction(programAccountIndex uint64) (uint64, error) {
	if len(instrCtx.ProgramAccounts) == 0 || programAccountIndex > uint64(len(instrCtx.ProgramAccounts)-1) {
		return 0, InstrErrNotEnoughAccountKeys
	}
	return instrCtx.ProgramAccounts[programAccountIndex], nil
}

func (instrCtx *InstructionCtx) NumberOfProgramAccounts() uint64 {
	return uint64(len(instrCtx.ProgramAccounts))
}

func (instrCtx *InstructionCtx) NumberOfInstructionAccounts() uint64 {
	return uint64(len(instrCtx.InstructionAccounts))
}

func (instrCtx *InstructionCtx) LastProgramKey(txCtx *TransactionCtx) (solana.PublicKey, error) {
	programAccountIndex := safemath.SaturatingSubU64(instrCtx.NumberOfProgramAccounts(), 1)

	index, err := instrCtx.IndexOfProgramAccountInTransaction(programAccountIndex)
	if err != nil {
		return solana.PublicKey{}, err
	}

	return txCtx.KeyOfAccountAtIndex(index)
}

func (instrCtx *InstructionCtx) IndexOfInstructionAccountInTransaction(instrAcctIdx uint64) (uint64, error) {
	if len(instrCtx.InstructionAccounts) == 0 || instrAcctIdx > uint64(len(instrCtx.InstructionAccounts)-1) {
		return 0, InstrErrNotEnoughAccountKeys
	}
	return instrCtx.InstructionAccounts[instrAcctIdx].IndexInTransaction, nil
}

func (instrCtx *InstructionCtx) IsInstructionAccountDuplicate(instrAcctIdx uint64) (bool, uint64, error) {
	if len(instrCtx.InstructionAccounts) == 0 || instrAcctIdx > uint64(len(instrCtx.InstructionAccounts)-1) {
		return false, 0, InstrErrNotEnoughAccountKeys
	}

	idxInCallee := instrCtx.InstructionAccounts[instrAcctIdx].IndexInCallee

	if idxInCallee == instrAcctIdx {
		return false, 0, nil
	} else {
		return true, idxInCallee, nil
	}
}

func (instrCtx *InstructionCtx) Configure(programAccts []uint64, instrAccts []InstructionAccount, instrData []byte) {
	instrCtx.ProgramAccounts = programAccts
	instrCtx.InstructionAccounts = instrAccts
	instrCtx.Data = instrData
}

func (instrCtx *InstructionCtx) BorrowAccount(txCtx *TransactionCtx, idxInTx uint64, idxInInstr uint64) (*BorrowedAccount, error) {
	account, err := txCtx.Accounts.GetAccount(idxInTx)
	if err != nil {
		return nil, err
	}
	borrowedAcct := BorrowedAccount{Account: account, TxCtx: txCtx, InstrCtx: instrCtx, IndexInTransaction: idxInTx, IndexInInstruction: idxInInstr}
	return &borrowedAcct, nil
}

func (instrCtx *InstructionCtx) BorrowInstructionAccount(txCtx *TransactionCtx, instrAcctIdx uint64) (*BorrowedAccount, error) {
	idxInTx, err := instrCtx.IndexOfInstructionAccountInTransaction(instrAcctIdx)
	if err != nil {
		return nil, err
	}
	idxInInstr := safemath.SaturatingAddU64(instrCtx.NumberOfProgramAccounts(), instrAcctIdx)
	return instrCtx.BorrowAccount(txCtx, idxInTx, idxInInstr)
}

func (instrCtx *InstructionCtx) BorrowProgramAccount(txCtx *TransactionCtx, programAcctIdx uint64) (*BorrowedAccount, error) {
	indexInTx, err := instrCtx.IndexOfProgramAccountInTransaction(programAcctIdx)
	if err != nil {
		return nil, err
	}
	return instrCtx.BorrowAccount(txCtx, indexInTx, programAcctIdx)
}

func (instrCtx *InstructionCtx) BorrowLastProgramAccount(txCtx *TransactionCtx) (*BorrowedAccount, error) {
	programAcctIdx := safemath.SaturatingSubU64(instrCtx.NumberOfProgramAccounts(), 1)
	return instrCtx.BorrowProgramAccount(txCtx, programAcctIdx)
}

func (instrCtx *InstructionCtx) IsInstructionAccountSigner(instrAcctIdx uint64) (bool, error) {
	if len(instrCtx.InstructionAccounts) == 0 || instrAcctIdx > uint64(len(instrCtx.InstructionAccounts)) {
		return false, InstrErrMissingAccount
	}

	return instrCtx.InstructionAccounts[instrAcctIdx].IsSigner, nil
}

func (instrCtx *InstructionCtx) BorrowExecutableAccount(txCtx *TransactionCtx, pubkey solana.PublicKey) (*BorrowedAccount, error) {
	for _, execAcct := range txCtx.ExecutableAccounts {
		if execAcct.Key() == pubkey && execAcct.AccountExists() {
			return &execAcct, nil
		}
	}
	return nil, fmt.Errorf("unknown account")
}

func (instrCtx *InstructionCtx) IsInstructionAccountWritable(instrAcctIdx uint64) (bool, error) {
	if len(instrCtx.InstructionAccounts) == 0 || instrAcctIdx > uint64(len(instrCtx.InstructionAccounts)) {
		return false, InstrErrMissingAccount
	}

	return instrCtx.InstructionAccounts[instrAcctIdx].IsWritable, nil
}

func (instrCtx *InstructionCtx) IndexOfInstructionAccount(txCtx *TransactionCtx, pubkey solana.PublicKey) (uint64, error) {
	for index, instrAcct := range instrCtx.InstructionAccounts {
		if txCtx.AccountKeys[instrAcct.IndexInTransaction] == pubkey {
			return uint64(index), nil
		}
	}
	return 0, InstrErrMissingAccount
}

func (instrCtx *InstructionCtx) StackHeight() uint64 {
	return instrCtx.NestingLevel + 1
}

func (instrCtx *InstructionCtx) CheckNumOfInstructionAccounts(num uint64) error {
	if instrCtx.NumberOfInstructionAccounts() < num {
		return InstrErrNotEnoughAccountKeys
	} else {
		return nil
	}
}

func (instrCtx *InstructionCtx) Signers(txCtx *TransactionCtx) ([]solana.PublicKey, error) {
	var signers []solana.PublicKey
	for _, ixAcct := range instrCtx.InstructionAccounts {
		if ixAcct.IsSigner {
			pk, err := txCtx.KeyOfAccountAtIndex(ixAcct.IndexInTransaction)
			if err != nil {
				return nil, err
			}
			signers = append(signers, pk)
		}
	}
	return signers, nil
}
