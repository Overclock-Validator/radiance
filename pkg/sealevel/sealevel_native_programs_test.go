package sealevel

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"testing"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/assert"
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

// Config program tests

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

	acctMetas := []AccountMeta{{Pubkey: configAcct.Key, IsSigner: true, IsWritable: true}}
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)

	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	require.NoError(t, err)
	acct, err := txCtx.Accounts.GetAccount(1)
	require.NoError(t, err)

	hasNewData := bytes.HasSuffix(acct.Data, []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))

	assert.Equal(t, true, hasNewData)
}

func TestExecute_Tx_Config_Program_With_Additional_Signer_Success(t *testing.T) {

	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: ConfigProgramAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	configAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	configAcctPubkey := configAcctPrivKey.PublicKey()

	authSignerPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authSignerPubKey := authSignerPrivKey.PublicKey()
	authSignerAcct := accounts.Account{Key: authSignerPubKey, Lamports: 0, Data: make([]byte, 500, 500), Owner: ConfigProgramAddr, Executable: false, RentEpoch: 100}

	// config account
	var configKeys []ConfigKey
	var ck ConfigKey
	ck.Pubkey = authSignerPubKey
	ck.IsSigner = true
	configKeys = append(configKeys, ck)
	acctBytes := marshalConfigKeys(configKeys)
	configAcct := accounts.Account{Key: configAcctPubkey, Lamports: 0, Data: acctBytes, Owner: ConfigProgramAddr, Executable: false, RentEpoch: 100}

	// instruction data
	var instrDataConfigKeys []ConfigKey
	var instrDataCk ConfigKey
	instrDataCk.Pubkey = authSignerPubKey
	instrDataCk.IsSigner = true
	instrDataConfigKeys = append(instrDataConfigKeys, instrDataCk)
	instrData := marshalConfigKeys(instrDataConfigKeys)

	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, configAcct, authSignerAcct})

	acctMetas := []AccountMeta{{Pubkey: configAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authSignerAcct.Key, IsSigner: true, IsWritable: true}}
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)

	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.NoError(t, err)
}

func TestExecute_Tx_Config_Program_With_Additional_Account_But_Not_As_Signer_Failure(t *testing.T) {

	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: ConfigProgramAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	configAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	configAcctPubkey := configAcctPrivKey.PublicKey()

	authSignerPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authSignerPubKey := authSignerPrivKey.PublicKey()
	authSignerAcct := accounts.Account{Key: authSignerPubKey, Lamports: 0, Data: make([]byte, 500, 500), Owner: ConfigProgramAddr, Executable: false, RentEpoch: 100}

	// config account
	var configKeys []ConfigKey
	var ck ConfigKey
	ck.Pubkey = authSignerPubKey
	ck.IsSigner = true
	configKeys = append(configKeys, ck)
	acctBytes := marshalConfigKeys(configKeys)
	configAcct := accounts.Account{Key: configAcctPubkey, Lamports: 0, Data: acctBytes, Owner: ConfigProgramAddr, Executable: false, RentEpoch: 100}

	// instruction data
	var instrDataConfigKeys []ConfigKey
	var instrDataCk ConfigKey
	instrDataCk.Pubkey = authSignerPubKey
	instrDataCk.IsSigner = true
	instrDataConfigKeys = append(instrDataConfigKeys, instrDataCk)
	instrData := marshalConfigKeys(instrDataConfigKeys)

	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, configAcct, authSignerAcct})

	acctMetas := []AccountMeta{{Pubkey: configAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: authSignerAcct.Key, IsSigner: false, IsWritable: true}}
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)

	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_Config_Program_Without_Config_Signer_Failure(t *testing.T) {
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

	acctMetas := []AccountMeta{{Pubkey: configAcct.Key, IsSigner: false, IsWritable: true}}
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)

	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_Config_Program_Without_Additional_Signer_Failure(t *testing.T) {

	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: ConfigProgramAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	configAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	configAcctPubkey := configAcctPrivKey.PublicKey()
	authSignerPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authSignerPubKey := authSignerPrivKey.PublicKey()

	// config account
	var configKeys []ConfigKey
	var ck ConfigKey
	ck.Pubkey = authSignerPubKey
	ck.IsSigner = true
	configKeys = append(configKeys, ck)
	acctBytes := marshalConfigKeys(configKeys)
	configAcct := accounts.Account{Key: configAcctPubkey, Lamports: 0, Data: acctBytes, Owner: ConfigProgramAddr, Executable: false, RentEpoch: 100}

	// incorrect signer
	randomPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	randomPubKey := randomPrivKey.PublicKey()
	randomPubKeyAcct := accounts.Account{Key: randomPubKey, Lamports: 0, Data: acctBytes, Owner: ConfigProgramAddr, Executable: false, RentEpoch: 100}

	// instruction data
	var instrDataConfigKeys []ConfigKey
	var instrDataCk ConfigKey
	instrDataCk.Pubkey = randomPubKey
	instrDataCk.IsSigner = true
	configKeys = append(instrDataConfigKeys, instrDataCk)
	instrData := marshalConfigKeys(instrDataConfigKeys)

	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, configAcct, randomPubKeyAcct})

	acctMetas := []AccountMeta{{Pubkey: configAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: randomPubKeyAcct.Key, IsSigner: true, IsWritable: true}}
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)

	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_Config_Program_Duplicate_New_Keys_Failure(t *testing.T) {

	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: ConfigProgramAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	configAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	configAcctPubkey := configAcctPrivKey.PublicKey()

	authSignerPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authSignerPubKey := authSignerPrivKey.PublicKey()
	authSignerAcct := accounts.Account{Key: authSignerPubKey, Lamports: 0, Data: make([]byte, 500, 500), Owner: ConfigProgramAddr, Executable: false, RentEpoch: 100}

	// config account
	var configKeys []ConfigKey
	var ck ConfigKey
	ck.Pubkey = authSignerPubKey
	ck.IsSigner = true
	configKeys = append(configKeys, ck)
	configKeysData := marshalConfigKeys(configKeys)
	acctBytes := make([]byte, len(configKeysData)+500)
	copy(acctBytes, configKeysData)
	configAcct := accounts.Account{Key: configAcctPubkey, Lamports: 0, Data: acctBytes, Owner: ConfigProgramAddr, Executable: false, RentEpoch: 100}

	// instruction data
	var instrDataConfigKeys []ConfigKey
	var instrDataCk ConfigKey
	instrDataCk.Pubkey = authSignerPubKey
	instrDataCk.IsSigner = true
	instrDataConfigKeys = append(instrDataConfigKeys, instrDataCk)
	instrDataConfigKeys = append(instrDataConfigKeys, instrDataCk) // duplicate keys in update data - should cause a failure (InvalidArgument)
	instrData := marshalConfigKeys(instrDataConfigKeys)

	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, configAcct, authSignerAcct})

	acctMetas := []AccountMeta{{Pubkey: configAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authSignerAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: authSignerAcct.Key, IsSigner: true, IsWritable: true}}
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)

	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidArgument, err)
}

// BPF loader tests

func TestExecute_Tx_BpfLoader_InitializeBuffer_Success(t *testing.T) {

	// buffer account
	bufferAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	bufferPubkey := bufferAcctPrivKey.PublicKey()
	bufferAcctData := make([]byte, 500)
	binary.LittleEndian.PutUint32(bufferAcctData, UpgradeableLoaderStateTypeUninitialized)
	bufferAcct := accounts.Account{Key: bufferPubkey, Lamports: 0, Data: []byte(bufferAcctData), Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	// authority account
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: false, IsWritable: true}, // uninit buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true}} // authority account
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)

	instrData := make([]byte, 4)
	binary.LittleEndian.AppendUint32(instrData, UpgradeableLoaderInstrTypeInitializeBuffer)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})

	assert.Equal(t, nil, err)
}

func TestExecute_Tx_BpfLoader_InitializeBuffer_Buffer_Acct_Already_Initialize_Failure(t *testing.T) {

	// buffer account
	bufferAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	bufferPubkey := bufferAcctPrivKey.PublicKey()
	bufferAcctData := make([]byte, 500)
	binary.LittleEndian.PutUint32(bufferAcctData, UpgradeableLoaderStateTypeBuffer) // buffer acct already initialized
	bufferAcct := accounts.Account{Key: bufferPubkey, Lamports: 0, Data: []byte(bufferAcctData), Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	// authority account
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: false, IsWritable: true}, // already initialize buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true}} // authority account
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)

	instrData := make([]byte, 4)
	binary.LittleEndian.AppendUint32(instrData, UpgradeableLoaderInstrTypeInitializeBuffer)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})

	assert.Equal(t, InstrErrAccountAlreadyInitialized, err)
}

func TestExecute_Tx_BpfLoader_Write_Success(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority account
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// buffer account
	bufferWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(bufferWriter)
	bufferAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeBuffer, Buffer: UpgradeableLoaderStateBuffer{AuthorityAddress: &authorityPubkey}}
	err = bufferAcctState.MarshalWithEncoder(encoder)
	bufferAcctBytes := bufferWriter.Bytes()
	bufferData := make([]byte, 500, 500)
	copy(bufferData, bufferAcctBytes)
	bufferAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	bufferPubkey := bufferAcctPrivKey.PublicKey()
	bufferAcct := accounts.Account{Key: bufferPubkey, Lamports: 0, Data: bufferData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	// bpf loader write instruction
	var writeInstr UpgradeableLoaderInstrWrite
	instrWriter := new(bytes.Buffer)
	instrEncoder := bin.NewBinEncoder(instrWriter)
	writeInstr.Offset = 20
	writeInstr.Bytes = make([]byte, 100)
	for count := 0; count < 100; count++ {
		writeInstr.Bytes[count] = 0x61
	}

	err = writeInstr.MarshalWithEncoder(instrEncoder)
	assert.NoError(t, err)

	instrData := instrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true}} // authority account
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, nil, err)
}

func TestExecute_Tx_BpfLoader_Write_Offset_Too_Large_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority account
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// buffer account
	bufferWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(bufferWriter)
	bufferAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeBuffer, Buffer: UpgradeableLoaderStateBuffer{AuthorityAddress: &authorityPubkey}}
	err = bufferAcctState.MarshalWithEncoder(encoder)
	bufferAcctBytes := bufferWriter.Bytes()
	bufferData := make([]byte, 500, 500)
	copy(bufferData, bufferAcctBytes)
	bufferAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	bufferPubkey := bufferAcctPrivKey.PublicKey()
	bufferAcct := accounts.Account{Key: bufferPubkey, Lamports: 0, Data: bufferData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	// bpf loader write instruction
	var writeInstr UpgradeableLoaderInstrWrite
	instrWriter := new(bytes.Buffer)
	instrEncoder := bin.NewBinEncoder(instrWriter)
	writeInstr.Offset = 600 // offset too large for buffer acct data size
	writeInstr.Bytes = make([]byte, 100)
	for count := 0; count < 100; count++ {
		writeInstr.Bytes[count] = 0x61
	}

	err = writeInstr.MarshalWithEncoder(instrEncoder)
	assert.NoError(t, err)

	instrData := instrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true}} // authority account
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrAccountDataTooSmall, err)
}

func TestExecute_Tx_BpfLoader_Write_Buffer_Authority_Didnt_Sign_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority account
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// buffer account
	bufferWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(bufferWriter)
	bufferAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeBuffer, Buffer: UpgradeableLoaderStateBuffer{AuthorityAddress: &authorityPubkey}}
	err = bufferAcctState.MarshalWithEncoder(encoder)
	bufferAcctBytes := bufferWriter.Bytes()
	bufferData := make([]byte, 500, 500)
	copy(bufferData, bufferAcctBytes)
	bufferAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	bufferPubkey := bufferAcctPrivKey.PublicKey()
	bufferAcct := accounts.Account{Key: bufferPubkey, Lamports: 0, Data: bufferData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	// bpf loader write instruction
	var writeInstr UpgradeableLoaderInstrWrite
	instrWriter := new(bytes.Buffer)
	instrEncoder := bin.NewBinEncoder(instrWriter)
	writeInstr.Offset = 20
	writeInstr.Bytes = make([]byte, 100)
	for count := 0; count < 100; count++ {
		writeInstr.Bytes[count] = 0x61
	}

	err = writeInstr.MarshalWithEncoder(instrEncoder)
	assert.NoError(t, err)

	instrData := instrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: true}} // authority account, not a signer
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_BpfLoader_Write_Incorrect_Authority_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// incorrect authority account
	incorrectAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	incorrectAuthorityPubkey := incorrectAuthorityPrivKey.PublicKey()
	incorrectAuthorityAcct := accounts.Account{Key: incorrectAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// authority pubkey for the buffer acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()

	// buffer account
	bufferWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(bufferWriter)
	bufferAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeBuffer, Buffer: UpgradeableLoaderStateBuffer{AuthorityAddress: &authorityPubkey}}
	err = bufferAcctState.MarshalWithEncoder(encoder)
	bufferAcctBytes := bufferWriter.Bytes()
	bufferData := make([]byte, 500, 500)
	copy(bufferData, bufferAcctBytes)
	bufferAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	bufferPubkey := bufferAcctPrivKey.PublicKey()
	bufferAcct := accounts.Account{Key: bufferPubkey, Lamports: 0, Data: bufferData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	// bpf loader write instruction
	var writeInstr UpgradeableLoaderInstrWrite
	instrWriter := new(bytes.Buffer)
	instrEncoder := bin.NewBinEncoder(instrWriter)
	writeInstr.Offset = 20
	writeInstr.Bytes = make([]byte, 100)
	for count := 0; count < 100; count++ {
		writeInstr.Bytes[count] = 0x61
	}

	err = writeInstr.MarshalWithEncoder(instrEncoder)
	assert.NoError(t, err)

	instrData := instrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, incorrectAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: incorrectAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // incorrec authority account for the buffer
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrIncorrectAuthority, err)
}
