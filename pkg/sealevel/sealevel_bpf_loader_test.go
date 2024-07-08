package sealevel

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"testing"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/assert"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/cu"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/global"
)

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

func TestExecute_Tx_BpfLoader_SetAuthority_Not_Enough_Instr_Accts_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	authorityPrivkey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivkey.PublicKey()

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

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthority)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}} // properly initialized buffer acct

	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrNotEnoughAccountKeys, err)
}

func TestExecute_Tx_BpfLoader_SetAuthority_Buffer_Success(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the buffer acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the buffer acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

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

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthority)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true},    // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, nil, err)
}

func TestExecute_Tx_BpfLoader_SetAuthority_ProgramData_Success(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the programdata acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the programdata acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// programdata account
	programDataWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(programDataWriter)
	programDataAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeProgramData, ProgramData: UpgradeableLoaderStateProgramData{UpgradeAuthorityAddress: &authorityPubkey}}
	err = programDataAcctState.MarshalWithEncoder(encoder)
	programDataAcctBytes := programDataWriter.Bytes()
	programDataData := make([]byte, 500, 500)
	copy(programDataData, programDataAcctBytes)
	programDataAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	programDataPubkey := programDataAcctPrivKey.PublicKey()
	programDataAcct := accounts.Account{Key: programDataPubkey, Lamports: 0, Data: programDataData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthority)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, programDataAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: programDataAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized programdata acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true},    // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, nil, err)
}

func TestExecute_Tx_BpfLoader_SetAuthority_Buffer_Immutable_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the buffer acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the buffer acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// buffer account
	bufferWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(bufferWriter)
	bufferAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeBuffer, Buffer: UpgradeableLoaderStateBuffer{AuthorityAddress: nil}}
	err = bufferAcctState.MarshalWithEncoder(encoder)
	bufferAcctBytes := bufferWriter.Bytes()
	bufferData := make([]byte, 500, 500)
	copy(bufferData, bufferAcctBytes)
	bufferAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	bufferPubkey := bufferAcctPrivKey.PublicKey()
	bufferAcct := accounts.Account{Key: bufferPubkey, Lamports: 0, Data: bufferData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthority)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true},    // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrImmutable, err)
}

func TestExecute_Tx_BpfLoader_SetAuthority_Buffer_Wrong_Upgrade_Authority_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the buffer acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()

	// new authority pubkey for the buffer acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// incorrect authority account
	incorrectAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	incorrectAuthorityPubkey := incorrectAuthorityPrivKey.PublicKey()
	incorrectAuthorityAcct := accounts.Account{Key: incorrectAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

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

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthority)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, incorrectAuthorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: incorrectAuthorityAcct.Key, IsSigner: true, IsWritable: true}, // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}}       // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrIncorrectAuthority, err)
}

func TestExecute_Tx_BpfLoader_SetAuthority_Buffer_Authority_Didnt_Sign_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the buffer acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the buffer acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

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

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthority)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: true},   // authority for the account, but not a signer
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_BpfLoader_SetAuthority_Buffer_No_New_Authority_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the buffer acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

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

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthority)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true}, // authority for the account
	} // no new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrIncorrectAuthority, err)
}

func TestExecute_Tx_BpfLoader_SetAuthority_Buffer_Uninitialized_Account_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the buffer acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the buffer acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// buffer account
	bufferWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(bufferWriter)
	bufferAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeUninitialized} // account is uninitialized, hence ineligible for SetAuthority instr
	err = bufferAcctState.MarshalWithEncoder(encoder)
	bufferAcctBytes := bufferWriter.Bytes()
	bufferData := make([]byte, 500, 500)
	copy(bufferData, bufferAcctBytes)
	bufferAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	bufferPubkey := bufferAcctPrivKey.PublicKey()
	bufferAcct := accounts.Account{Key: bufferPubkey, Lamports: 0, Data: bufferData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthority)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // uninitialized buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true},    // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidArgument, err)
}

func TestExecute_Tx_BpfLoader_SetAuthority_ProgramData_Immutable_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the programdata acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the programdata acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// programdata account
	programDataWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(programDataWriter)
	programDataAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeProgramData, ProgramData: UpgradeableLoaderStateProgramData{UpgradeAuthorityAddress: nil}}
	err = programDataAcctState.MarshalWithEncoder(encoder)
	programDataAcctBytes := programDataWriter.Bytes()
	programDataData := make([]byte, 500, 500)
	copy(programDataData, programDataAcctBytes)
	programDataAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	programDataPubkey := programDataAcctPrivKey.PublicKey()
	programDataAcct := accounts.Account{Key: programDataPubkey, Lamports: 0, Data: programDataData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthority)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, programDataAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: programDataAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized programdata acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true},    // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrImmutable, err)
}

func TestExecute_Tx_BpfLoader_SetAuthority_ProgramData_Authority_Didnt_Sign_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the programdata acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the programdata acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// programdata account
	programDataWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(programDataWriter)
	programDataAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeProgramData, ProgramData: UpgradeableLoaderStateProgramData{UpgradeAuthorityAddress: &authorityPubkey}}
	err = programDataAcctState.MarshalWithEncoder(encoder)
	programDataAcctBytes := programDataWriter.Bytes()
	programDataData := make([]byte, 500, 500)
	copy(programDataData, programDataAcctBytes)
	programDataAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	programDataPubkey := programDataAcctPrivKey.PublicKey()
	programDataAcct := accounts.Account{Key: programDataPubkey, Lamports: 0, Data: programDataData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthority)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, programDataAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: programDataAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized programdata acct
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: true},   // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_BpfLoader_SetAuthority_ProgramData_Wrong_Authority_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the programdata acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()

	// new authority pubkey for the programdata acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// incorrect authority account
	incorrectAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	incorrectAuthorityPubkey := incorrectAuthorityPrivKey.PublicKey()
	incorrectAuthorityAcct := accounts.Account{Key: incorrectAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// programdata account
	programDataWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(programDataWriter)
	programDataAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeProgramData, ProgramData: UpgradeableLoaderStateProgramData{UpgradeAuthorityAddress: &authorityPubkey}}
	err = programDataAcctState.MarshalWithEncoder(encoder)
	programDataAcctBytes := programDataWriter.Bytes()
	programDataData := make([]byte, 500, 500)
	copy(programDataData, programDataAcctBytes)
	programDataAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	programDataPubkey := programDataAcctPrivKey.PublicKey()
	programDataAcct := accounts.Account{Key: programDataPubkey, Lamports: 0, Data: programDataData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthority)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, programDataAcct, incorrectAuthorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: programDataAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized programdata acct
		{Pubkey: incorrectAuthorityAcct.Key, IsSigner: false, IsWritable: true}, // incorrect authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}}        // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrIncorrectAuthority, err)
}

func TestExecute_Tx_BpfLoader_SetAuthorityChecked_Not_Enough_Instr_Accts_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	authorityPrivkey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivkey.PublicKey()

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

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthorityChecked)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}} // properly initialized buffer acct

	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.EnableBpfLoaderSetAuthorityCheckedIx, 0)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault(), GlobalCtx: global.GlobalCtx{Features: *f}}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrNotEnoughAccountKeys, err)
}

func TestExecute_Tx_BpfLoader_SetAuthorityChecked_Buffer_Success(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the buffer acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the buffer acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

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

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthorityChecked)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true},    // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.EnableBpfLoaderSetAuthorityCheckedIx, 0)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault(), GlobalCtx: global.GlobalCtx{Features: *f}}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, nil, err)
}

func TestExecute_Tx_BpfLoader_SetAuthorityChecked_ProgramData_Success(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the programdata acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the programdata acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// programdata account
	programDataWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(programDataWriter)
	programDataAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeProgramData, ProgramData: UpgradeableLoaderStateProgramData{UpgradeAuthorityAddress: &authorityPubkey}}
	err = programDataAcctState.MarshalWithEncoder(encoder)
	programDataAcctBytes := programDataWriter.Bytes()
	programDataData := make([]byte, 500, 500)
	copy(programDataData, programDataAcctBytes)
	programDataAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	programDataPubkey := programDataAcctPrivKey.PublicKey()
	programDataAcct := accounts.Account{Key: programDataPubkey, Lamports: 0, Data: programDataData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthorityChecked)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, programDataAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: programDataAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized programdata acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true},    // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.EnableBpfLoaderSetAuthorityCheckedIx, 0)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault(), GlobalCtx: global.GlobalCtx{Features: *f}}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, nil, err)
}

func TestExecute_Tx_BpfLoader_SetAuthorityChecked_Buffer_Immutable_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the buffer acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the buffer acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// buffer account
	bufferWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(bufferWriter)
	bufferAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeBuffer, Buffer: UpgradeableLoaderStateBuffer{AuthorityAddress: nil}}
	err = bufferAcctState.MarshalWithEncoder(encoder)
	bufferAcctBytes := bufferWriter.Bytes()
	bufferData := make([]byte, 500, 500)
	copy(bufferData, bufferAcctBytes)
	bufferAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	bufferPubkey := bufferAcctPrivKey.PublicKey()
	bufferAcct := accounts.Account{Key: bufferPubkey, Lamports: 0, Data: bufferData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthorityChecked)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true},    // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.EnableBpfLoaderSetAuthorityCheckedIx, 0)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault(), GlobalCtx: global.GlobalCtx{Features: *f}}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrImmutable, err)
}

func TestExecute_Tx_BpfLoader_SetAuthorityChecked_Buffer_Wrong_Upgrade_Authority_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the buffer acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()

	// new authority pubkey for the buffer acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// incorrect authority account
	incorrectAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	incorrectAuthorityPubkey := incorrectAuthorityPrivKey.PublicKey()
	incorrectAuthorityAcct := accounts.Account{Key: incorrectAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

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

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthorityChecked)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, incorrectAuthorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: incorrectAuthorityAcct.Key, IsSigner: true, IsWritable: true}, // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}}       // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.EnableBpfLoaderSetAuthorityCheckedIx, 0)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault(), GlobalCtx: global.GlobalCtx{Features: *f}}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrIncorrectAuthority, err)
}

func TestExecute_Tx_BpfLoader_SetAuthorityChecked_Buffer_Authority_Didnt_Sign_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the buffer acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the buffer acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

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

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthorityChecked)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: true},   // authority for the account, but not a signer
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.EnableBpfLoaderSetAuthorityCheckedIx, 0)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault(), GlobalCtx: global.GlobalCtx{Features: *f}}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_BpfLoader_SetAuthorityChecked_Buffer_New_Authority_Didnt_Sign_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the buffer acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the buffer acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

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

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthorityChecked)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true},     // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: false, IsWritable: true}} // new authority but not a signer
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.EnableBpfLoaderSetAuthorityCheckedIx, 0)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault(), GlobalCtx: global.GlobalCtx{Features: *f}}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_BpfLoader_SetAuthorityChecked_Buffer_Uninitialized_Account_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the buffer acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the buffer acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// buffer account
	bufferWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(bufferWriter)
	bufferAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeUninitialized} // account is uninitialized, hence ineligible for SetAuthority instr
	err = bufferAcctState.MarshalWithEncoder(encoder)
	bufferAcctBytes := bufferWriter.Bytes()
	bufferData := make([]byte, 500, 500)
	copy(bufferData, bufferAcctBytes)
	bufferAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	bufferPubkey := bufferAcctPrivKey.PublicKey()
	bufferAcct := accounts.Account{Key: bufferPubkey, Lamports: 0, Data: bufferData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthorityChecked)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, bufferAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: bufferAcct.Key, IsSigner: true, IsWritable: true}, // uninitialized buffer acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true},    // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.EnableBpfLoaderSetAuthorityCheckedIx, 0)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault(), GlobalCtx: global.GlobalCtx{Features: *f}}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidArgument, err)
}

func TestExecute_Tx_BpfLoader_SetAuthorityChecked_ProgramData_Immutable_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the programdata acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the programdata acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// programdata account
	programDataWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(programDataWriter)
	programDataAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeProgramData, ProgramData: UpgradeableLoaderStateProgramData{UpgradeAuthorityAddress: nil}}
	err = programDataAcctState.MarshalWithEncoder(encoder)
	programDataAcctBytes := programDataWriter.Bytes()
	programDataData := make([]byte, 500, 500)
	copy(programDataData, programDataAcctBytes)
	programDataAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	programDataPubkey := programDataAcctPrivKey.PublicKey()
	programDataAcct := accounts.Account{Key: programDataPubkey, Lamports: 0, Data: programDataData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthorityChecked)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, programDataAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: programDataAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized programdata acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true},    // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.EnableBpfLoaderSetAuthorityCheckedIx, 0)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault(), GlobalCtx: global.GlobalCtx{Features: *f}}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrImmutable, err)
}

func TestExecute_Tx_BpfLoader_SetAuthorityChecked_ProgramData_Authority_Didnt_Sign_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the programdata acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the programdata acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// programdata account
	programDataWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(programDataWriter)
	programDataAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeProgramData, ProgramData: UpgradeableLoaderStateProgramData{UpgradeAuthorityAddress: &authorityPubkey}}
	err = programDataAcctState.MarshalWithEncoder(encoder)
	programDataAcctBytes := programDataWriter.Bytes()
	programDataData := make([]byte, 500, 500)
	copy(programDataData, programDataAcctBytes)
	programDataAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	programDataPubkey := programDataAcctPrivKey.PublicKey()
	programDataAcct := accounts.Account{Key: programDataPubkey, Lamports: 0, Data: programDataData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthorityChecked)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, programDataAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: programDataAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized programdata acct
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: true},   // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}} // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.EnableBpfLoaderSetAuthorityCheckedIx, 0)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault(), GlobalCtx: global.GlobalCtx{Features: *f}}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_BpfLoader_SetAuthorityChecked_ProgramData_New_Authority_Didnt_Sign_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the programdata acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// new authority pubkey for the programdata acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// programdata account
	programDataWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(programDataWriter)
	programDataAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeProgramData, ProgramData: UpgradeableLoaderStateProgramData{UpgradeAuthorityAddress: &authorityPubkey}}
	err = programDataAcctState.MarshalWithEncoder(encoder)
	programDataAcctBytes := programDataWriter.Bytes()
	programDataData := make([]byte, 500, 500)
	copy(programDataData, programDataAcctBytes)
	programDataAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	programDataPubkey := programDataAcctPrivKey.PublicKey()
	programDataAcct := accounts.Account{Key: programDataPubkey, Lamports: 0, Data: programDataData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthorityChecked)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, programDataAcct, authorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: programDataAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized programdata acct
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true},     // authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: false, IsWritable: true}} // new authority, but not a signer
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.EnableBpfLoaderSetAuthorityCheckedIx, 0)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault(), GlobalCtx: global.GlobalCtx{Features: *f}}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_BpfLoader_SetAuthorityChecked_ProgramData_Wrong_Authority_Failure(t *testing.T) {
	// bpf loader acct
	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: BpfLoaderUpgradeableAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority pubkey for the programdata acct
	authorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivKey.PublicKey()

	// new authority pubkey for the programdata acct
	newAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newAuthorityPubkey := newAuthorityPrivKey.PublicKey()
	newAuthorityAcct := accounts.Account{Key: newAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: true, RentEpoch: 100}

	// incorrect authority account
	incorrectAuthorityPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	incorrectAuthorityPubkey := incorrectAuthorityPrivKey.PublicKey()
	incorrectAuthorityAcct := accounts.Account{Key: incorrectAuthorityPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// programdata account
	programDataWriter := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(programDataWriter)
	programDataAcctState := UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeProgramData, ProgramData: UpgradeableLoaderStateProgramData{UpgradeAuthorityAddress: &authorityPubkey}}
	err = programDataAcctState.MarshalWithEncoder(encoder)
	programDataAcctBytes := programDataWriter.Bytes()
	programDataData := make([]byte, 500, 500)
	copy(programDataData, programDataAcctBytes)
	programDataAcctPrivKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	programDataPubkey := programDataAcctPrivKey.PublicKey()
	programDataAcct := accounts.Account{Key: programDataPubkey, Lamports: 0, Data: programDataData, Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	instrData := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrData, UpgradeableLoaderInstrTypeSetAuthorityChecked)
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct, programDataAcct, incorrectAuthorityAcct, newAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: programDataAcct.Key, IsSigner: true, IsWritable: true}, // properly initialized programdata acct
		{Pubkey: incorrectAuthorityAcct.Key, IsSigner: false, IsWritable: true}, // incorrect authority for the account
		{Pubkey: newAuthorityAcct.Key, IsSigner: true, IsWritable: true}}        // new authority
	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.EnableBpfLoaderSetAuthorityCheckedIx, 0)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault(), GlobalCtx: global.GlobalCtx{Features: *f}}
	err = execCtx.ProcessInstruction(instrData, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrIncorrectAuthority, err)
}
