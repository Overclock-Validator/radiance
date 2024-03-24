package sealevel

import (
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/safemath"
)

type InstructionCtx struct {
	programId       solana.PublicKey
	ProgramAccounts []uint64
}

func (instrCtx InstructionCtx) ProgramId() solana.PublicKey {
	return instrCtx.programId
}

func (instrCtx InstructionCtx) IndexOfProgramAccountInTransaction(programAccountIndex uint64) (uint64, error) {
	if len(instrCtx.ProgramAccounts) == 0 || programAccountIndex > uint64(len(instrCtx.ProgramAccounts)-1) {
		return 0, NotEnoughAccountKeys
	}
	return instrCtx.ProgramAccounts[programAccountIndex], nil
}

func (instrCtx InstructionCtx) NumberOfProgramAccounts() uint64 {
	return uint64(len(instrCtx.ProgramAccounts))
}

func (instrCtx InstructionCtx) LastProgramKey(txCtx TransactionCtx) (solana.PublicKey, error) {
	programAccountIndex := safemath.SaturatingSubU64(instrCtx.NumberOfProgramAccounts(), 1)

	index, err := instrCtx.IndexOfProgramAccountInTransaction(programAccountIndex)
	if err != nil {
		return solana.PublicKey{}, err
	}

	return txCtx.KeyOfAccountAtIndex(index)
}
