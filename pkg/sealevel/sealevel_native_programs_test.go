package sealevel

import (
	"bytes"
	_ "embed"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/cu"
)

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

func TestExecute_Tx_Config_Program_Success(t *testing.T) {

	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: ConfigProgramAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	configAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	configAcctPubkey := configAcctPrivKey.PublicKey()

	var configKeys []ConfigKey

	for i := 0; i < 5; i++ {
		var ck ConfigKey
		ck.Pubkey = configAcctPubkey
		ck.IsSigner = true
		configKeys = append(configKeys, ck)
	}

	ckBytes := marshalConfigKeys(configKeys)

	instrData := make([]byte, len(ckBytes)+100, len(ckBytes)+100)
	copy(instrData, ckBytes)
	instrData = append(instrData, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"...)

	acctBytes := make([]byte, len(ckBytes)+200, len(ckBytes)+200)
	copy(acctBytes, ckBytes)

	configAcct := accounts.Account{Key: configAcctPubkey, Lamports: 0, Data: acctBytes, Owner: ConfigProgramAddr, Executable: false, RentEpoch: 100}

	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, configAcct})

	instructionAccts := []InstructionAccount{
		{IndexInTransaction: 1, IndexInCaller: 0, IndexInCallee: 0, IsSigner: true, IsWritable: true},
	}

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)

	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	require.NoError(t, err)
	acct, err := txCtx.Accounts.GetAccount(1)
	require.NoError(t, err)

	hasNewData := bytes.HasSuffix(acct.Data, []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))

	assert.Equal(t, true, hasNewData)
}
