package sealevel

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/cu"
)

// ComputeBudget program tests

func TestExecute_Tx_ComputeBudget_Program(t *testing.T) {

	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: ComputeBudgetProgramAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct})

	instructionAccts := []InstructionAccount{
		{IndexInTransaction: 0, IndexInCaller: 0, IndexInCallee: 0, IsSigner: true, IsWritable: true},
	}

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)

	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err := execCtx.ProcessInstruction([]byte{}, instructionAccts, []uint64{0})
	require.NoError(t, err)
}
