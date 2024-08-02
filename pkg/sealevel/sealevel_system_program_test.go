package sealevel

import (
	"bytes"
	"testing"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/assert"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/cu"
	"k8s.io/klog/v2"
)

func TestExecute_Tx_System_Program_CreateAccount_Success(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// funding acct
	fundingAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	fundingPubkey := fundingAcctPrivateKey.PublicKey()
	fundingAcct := accounts.Account{Key: fundingPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// new acct
	newAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newPubkey := newAcctPrivateKey.PublicKey()
	newAcct := accounts.Account{Key: newPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	var createAcct SystemInstrCreateAccount
	createAcct.Lamports = 1234
	createAcct.Owner = BpfLoaderUpgradeableAddr
	createAcct.Space = 1234

	createAcctInstrWriter := new(bytes.Buffer)
	createAcctEncoder := bin.NewBinEncoder(createAcctInstrWriter)

	err = createAcct.MarshalWithEncoder(createAcctEncoder)
	assert.NoError(t, err)
	instrBytes := createAcctInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, fundingAcct, newAcct})

	acctMetas := []AccountMeta{{Pubkey: fundingAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: newAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	klog.Infof("pubkey: %s, %s", fundingAcct.Key, newAcct.Key)
	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.NoError(t, err)

	newAcctPost, err := txCtx.Accounts.GetAccount(2)
	assert.NoError(t, err)

	// check new account has lamports, space and owner as expected
	assert.Equal(t, createAcct.Lamports, newAcctPost.Lamports)
	assert.Equal(t, createAcct.Space, uint64(len(newAcctPost.Data)))
	assert.Equal(t, createAcct.Owner, solana.PublicKeyFromBytes(newAcctPost.Owner[:]))

	fundingAcctPost, err := txCtx.Accounts.GetAccount(1)
	assert.NoError(t, err)

	// check that the funder account balance has changed accordingly
	assert.Equal(t, fundingAcct.Lamports-createAcct.Lamports, fundingAcctPost.Lamports)
}

func TestExecute_Tx_System_Program_CreateAccount_Not_Enough_Accts_Failure(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// funding acct
	fundingAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	fundingPubkey := fundingAcctPrivateKey.PublicKey()
	fundingAcct := accounts.Account{Key: fundingPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	var createAcct SystemInstrCreateAccount
	createAcct.Lamports = 1234
	createAcct.Owner = BpfLoaderUpgradeableAddr
	createAcct.Space = 1234

	createAcctInstrWriter := new(bytes.Buffer)
	createAcctEncoder := bin.NewBinEncoder(createAcctInstrWriter)

	err = createAcct.MarshalWithEncoder(createAcctEncoder)
	assert.NoError(t, err)
	instrBytes := createAcctInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, fundingAcct})

	acctMetas := []AccountMeta{{Pubkey: fundingAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrNotEnoughAccountKeys, err)
}

func TestExecute_Tx_System_Program_CreateAccount_New_Acct_Has_Lamports_Failure(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// funding acct
	fundingAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	fundingPubkey := fundingAcctPrivateKey.PublicKey()
	fundingAcct := accounts.Account{Key: fundingPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// new acct
	newAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newPubkey := newAcctPrivateKey.PublicKey()
	newAcct := accounts.Account{Key: newPubkey, Lamports: 1000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	var createAcct SystemInstrCreateAccount
	createAcct.Lamports = 1234
	createAcct.Owner = BpfLoaderUpgradeableAddr
	createAcct.Space = 1234

	createAcctInstrWriter := new(bytes.Buffer)
	createAcctEncoder := bin.NewBinEncoder(createAcctInstrWriter)

	err = createAcct.MarshalWithEncoder(createAcctEncoder)
	assert.NoError(t, err)
	instrBytes := createAcctInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, fundingAcct, newAcct})

	acctMetas := []AccountMeta{{Pubkey: fundingAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: newAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	klog.Infof("pubkey: %s, %s", fundingAcct.Key, newAcct.Key)
	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, SystemProgErrAccountAlreadyInUse, err)
}

func TestExecute_Tx_System_Program_CreateAccount_New_Acct_Not_Signer_Failure(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// funding acct
	fundingAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	fundingPubkey := fundingAcctPrivateKey.PublicKey()
	fundingAcct := accounts.Account{Key: fundingPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// new acct
	newAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newPubkey := newAcctPrivateKey.PublicKey()
	newAcct := accounts.Account{Key: newPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	var createAcct SystemInstrCreateAccount
	createAcct.Lamports = 1234
	createAcct.Owner = BpfLoaderUpgradeableAddr
	createAcct.Space = 1234

	createAcctInstrWriter := new(bytes.Buffer)
	createAcctEncoder := bin.NewBinEncoder(createAcctInstrWriter)

	err = createAcct.MarshalWithEncoder(createAcctEncoder)
	assert.NoError(t, err)
	instrBytes := createAcctInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, fundingAcct, newAcct})

	acctMetas := []AccountMeta{{Pubkey: fundingAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: newAcct.Key, IsSigner: false, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	klog.Infof("pubkey: %s, %s", fundingAcct.Key, newAcct.Key)
	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_System_Program_CreateAccount_Too_Much_Space_Allocated_Failure(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// funding acct
	fundingAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	fundingPubkey := fundingAcctPrivateKey.PublicKey()
	fundingAcct := accounts.Account{Key: fundingPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// new acct
	newAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newPubkey := newAcctPrivateKey.PublicKey()
	newAcct := accounts.Account{Key: newPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	var createAcct SystemInstrCreateAccount
	createAcct.Lamports = 1234
	createAcct.Owner = BpfLoaderUpgradeableAddr
	createAcct.Space = SystemProgMaxPermittedDataLen + 10

	createAcctInstrWriter := new(bytes.Buffer)
	createAcctEncoder := bin.NewBinEncoder(createAcctInstrWriter)

	err = createAcct.MarshalWithEncoder(createAcctEncoder)
	assert.NoError(t, err)
	instrBytes := createAcctInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, fundingAcct, newAcct})

	acctMetas := []AccountMeta{{Pubkey: fundingAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: newAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	klog.Infof("pubkey: %s, %s", fundingAcct.Key, newAcct.Key)
	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, SystemProgErrInvalidAccountDataLength, err)
}

func TestExecute_Tx_System_Program_CreateAccount_New_Acct_Has_Data_Failure(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// funding acct
	fundingAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	fundingPubkey := fundingAcctPrivateKey.PublicKey()
	fundingAcct := accounts.Account{Key: fundingPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// new acct
	newAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newPubkey := newAcctPrivateKey.PublicKey()
	newAcct := accounts.Account{Key: newPubkey, Lamports: 0, Data: make([]byte, 1000), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	var createAcct SystemInstrCreateAccount
	createAcct.Lamports = 1234
	createAcct.Owner = BpfLoaderUpgradeableAddr
	createAcct.Space = 1234

	createAcctInstrWriter := new(bytes.Buffer)
	createAcctEncoder := bin.NewBinEncoder(createAcctInstrWriter)

	err = createAcct.MarshalWithEncoder(createAcctEncoder)
	assert.NoError(t, err)
	instrBytes := createAcctInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, fundingAcct, newAcct})

	acctMetas := []AccountMeta{{Pubkey: fundingAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: newAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	klog.Infof("pubkey: %s, %s", fundingAcct.Key, newAcct.Key)
	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, SystemProgErrAccountAlreadyInUse, err)
}

func TestExecute_Tx_System_Program_CreateAccount_New_Acct_Not_Owned_By_System_Failure(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// funding acct
	fundingAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	fundingPubkey := fundingAcctPrivateKey.PublicKey()
	fundingAcct := accounts.Account{Key: fundingPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// new acct
	newAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newPubkey := newAcctPrivateKey.PublicKey()
	newAcct := accounts.Account{Key: newPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	var createAcct SystemInstrCreateAccount
	createAcct.Lamports = 1234
	createAcct.Owner = BpfLoaderUpgradeableAddr
	createAcct.Space = 1234

	createAcctInstrWriter := new(bytes.Buffer)
	createAcctEncoder := bin.NewBinEncoder(createAcctInstrWriter)

	err = createAcct.MarshalWithEncoder(createAcctEncoder)
	assert.NoError(t, err)
	instrBytes := createAcctInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, fundingAcct, newAcct})

	acctMetas := []AccountMeta{{Pubkey: fundingAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: newAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	klog.Infof("pubkey: %s, %s", fundingAcct.Key, newAcct.Key)
	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, SystemProgErrAccountAlreadyInUse, err)
}

func TestExecute_Tx_System_Program_CreateAccount_Funding_Acct_Not_Signer(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// funding acct
	fundingAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	fundingPubkey := fundingAcctPrivateKey.PublicKey()
	fundingAcct := accounts.Account{Key: fundingPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// new acct
	newAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newPubkey := newAcctPrivateKey.PublicKey()
	newAcct := accounts.Account{Key: newPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	var createAcct SystemInstrCreateAccount
	createAcct.Lamports = 1234
	createAcct.Owner = BpfLoaderUpgradeableAddr
	createAcct.Space = 1234

	createAcctInstrWriter := new(bytes.Buffer)
	createAcctEncoder := bin.NewBinEncoder(createAcctInstrWriter)

	err = createAcct.MarshalWithEncoder(createAcctEncoder)
	assert.NoError(t, err)
	instrBytes := createAcctInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, fundingAcct, newAcct})

	acctMetas := []AccountMeta{{Pubkey: fundingAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: newAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	klog.Infof("pubkey: %s, %s", fundingAcct.Key, newAcct.Key)
	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_System_Program_Assign_Success(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// new acct
	newAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newPubkey := newAcctPrivateKey.PublicKey()
	newAcct := accounts.Account{Key: newPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	assignInstrWriter := new(bytes.Buffer)
	assignEncoder := bin.NewBinEncoder(assignInstrWriter)

	var assign SystemInstrAssign
	assign.Owner = BpfLoaderUpgradeableAddr
	err = assign.MarshalWithEncoder(assignEncoder)
	assert.NoError(t, err)
	instrBytes := assignInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, newAcct})

	acctMetas := []AccountMeta{{Pubkey: newAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, nil, err)

	acctPost, err := txCtx.Accounts.GetAccount(1)
	assert.NoError(t, err)

	assert.Equal(t, BpfLoaderUpgradeableAddr, acctPost.Owner)
}

func TestExecute_Tx_System_Program_Assign_Not_Signer_Failure(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// new acct
	newAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newPubkey := newAcctPrivateKey.PublicKey()
	newAcct := accounts.Account{Key: newPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	assignInstrWriter := new(bytes.Buffer)
	assignEncoder := bin.NewBinEncoder(assignInstrWriter)

	var assign SystemInstrAssign
	assign.Owner = BpfLoaderUpgradeableAddr
	err = assign.MarshalWithEncoder(assignEncoder)
	assert.NoError(t, err)
	instrBytes := assignInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, newAcct})

	acctMetas := []AccountMeta{{Pubkey: newAcct.Key, IsSigner: false, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_System_Program_Transfer_Success(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// funding acct
	fundingAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	fundingPubkey := fundingAcctPrivateKey.PublicKey()
	fundingAcct := accounts.Account{Key: fundingPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// recipient acct
	recipientPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	recipientPubkey := recipientPrivateKey.PublicKey()
	recipientAcct := accounts.Account{Key: recipientPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	var transfer SystemInstrTransfer
	transfer.Lamports = 1337

	transferInstrWriter := new(bytes.Buffer)
	transferEncoder := bin.NewBinEncoder(transferInstrWriter)

	err = transfer.MarshalWithEncoder(transferEncoder)
	assert.NoError(t, err)
	instrBytes := transferInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, fundingAcct, recipientAcct})

	acctMetas := []AccountMeta{{Pubkey: fundingAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: recipientAcct.Key, IsSigner: false, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.NoError(t, err)

	fundingAcctPost, err := txCtx.Accounts.GetAccount(1)
	assert.NoError(t, err)
	assert.Equal(t, fundingAcct.Lamports-transfer.Lamports, fundingAcctPost.Lamports)

	recipientAcctPost, err := txCtx.Accounts.GetAccount(2)
	assert.NoError(t, err)
	assert.Equal(t, transfer.Lamports, recipientAcctPost.Lamports)
}

func TestExecute_Tx_System_Program_Transfer_From_Not_Signer_Failure(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// funding acct
	fundingAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	fundingPubkey := fundingAcctPrivateKey.PublicKey()
	fundingAcct := accounts.Account{Key: fundingPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// recipient acct
	recipientPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	recipientPubkey := recipientPrivateKey.PublicKey()
	recipientAcct := accounts.Account{Key: recipientPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	var transfer SystemInstrTransfer
	transfer.Lamports = 1337

	transferInstrWriter := new(bytes.Buffer)
	transferEncoder := bin.NewBinEncoder(transferInstrWriter)

	err = transfer.MarshalWithEncoder(transferEncoder)
	assert.NoError(t, err)
	instrBytes := transferInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, fundingAcct, recipientAcct})

	acctMetas := []AccountMeta{{Pubkey: fundingAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: recipientAcct.Key, IsSigner: false, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_Tx_System_Program_Transfer_From_Has_Data_Failure(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// funding acct
	fundingAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	fundingPubkey := fundingAcctPrivateKey.PublicKey()
	fundingAcct := accounts.Account{Key: fundingPubkey, Lamports: 10000, Data: make([]byte, 100), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// recipient acct
	recipientPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	recipientPubkey := recipientPrivateKey.PublicKey()
	recipientAcct := accounts.Account{Key: recipientPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	var transfer SystemInstrTransfer
	transfer.Lamports = 1337

	transferInstrWriter := new(bytes.Buffer)
	transferEncoder := bin.NewBinEncoder(transferInstrWriter)

	err = transfer.MarshalWithEncoder(transferEncoder)
	assert.NoError(t, err)
	instrBytes := transferInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, fundingAcct, recipientAcct})

	acctMetas := []AccountMeta{{Pubkey: fundingAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: recipientAcct.Key, IsSigner: false, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidArgument, err)
}

func TestExecute_Tx_System_Program_Transfer_Not_Enough_Lamports_In_From_Acct(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// funding acct
	fundingAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	fundingPubkey := fundingAcctPrivateKey.PublicKey()
	fundingAcct := accounts.Account{Key: fundingPubkey, Lamports: 100, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// recipient acct
	recipientPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	recipientPubkey := recipientPrivateKey.PublicKey()
	recipientAcct := accounts.Account{Key: recipientPubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	var transfer SystemInstrTransfer
	transfer.Lamports = 1000000

	transferInstrWriter := new(bytes.Buffer)
	transferEncoder := bin.NewBinEncoder(transferInstrWriter)

	err = transfer.MarshalWithEncoder(transferEncoder)
	assert.NoError(t, err)
	instrBytes := transferInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, fundingAcct, recipientAcct})

	acctMetas := []AccountMeta{{Pubkey: fundingAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: recipientAcct.Key, IsSigner: false, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, SystemProgErrResultWithNegativeLamports, err)
}

func TestExecute_Tx_System_Program_AssignWithSeed_Success(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// base acct
	basePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	basePubkey := basePrivateKey.PublicKey()
	baseAcct := accounts.Account{Key: basePubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	assignedPubkey, err := solana.CreateWithSeed(basePubkey, "seed", BpfLoaderUpgradeableAddr)
	assert.NoError(t, err)

	assignedAcct := accounts.Account{Key: assignedPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	assert.NoError(t, err)
	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, assignedAcct, baseAcct})

	acctMetas := []AccountMeta{{Pubkey: assignedAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: baseAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	instrWriter := new(bytes.Buffer)
	instrEncoder := bin.NewBinEncoder(instrWriter)
	var assignWithSeed SystemInstrAssignWithSeed
	assignWithSeed.Base = basePubkey
	assignWithSeed.Owner = BpfLoaderUpgradeableAddr
	assignWithSeed.Seed = "seed"
	err = assignWithSeed.MarshalWithEncoder(instrEncoder)
	assert.NoError(t, err)

	instrBytes := instrWriter.Bytes()

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, nil, err)

	assignedAcctPost, err := txCtx.Accounts.GetAccount(1)
	assert.NoError(t, err)

	assert.Equal(t, assignWithSeed.Owner, solana.PublicKeyFromBytes(assignedAcctPost.Owner[:]))
}

func TestExecute_Tx_System_Program_AssignWithSeed_Addr_Doesnt_Match_Derived_Addr_Failure(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// base acct
	basePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	basePubkey := basePrivateKey.PublicKey()
	baseAcct := accounts.Account{Key: basePubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	// base acct
	wrongBasePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	wrongBasePubkey := wrongBasePrivateKey.PublicKey()
	wrongBaseAcct := accounts.Account{Key: wrongBasePubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	assert.NoError(t, err)
	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, wrongBaseAcct, baseAcct})

	acctMetas := []AccountMeta{{Pubkey: wrongBaseAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: baseAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	instrWriter := new(bytes.Buffer)
	instrEncoder := bin.NewBinEncoder(instrWriter)
	var assignWithSeed SystemInstrAssignWithSeed
	assignWithSeed.Base = basePubkey
	assignWithSeed.Owner = BpfLoaderUpgradeableAddr
	assignWithSeed.Seed = "seed"
	err = assignWithSeed.MarshalWithEncoder(instrEncoder)
	assert.NoError(t, err)

	instrBytes := instrWriter.Bytes()

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, SystemProgErrAddressWithSeedMismatch, err)
}

func TestExecute_Tx_System_Program_AssignWithSeed_Base_Not_Signer_Failure(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// base acct
	basePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	basePubkey := basePrivateKey.PublicKey()
	baseAcct := accounts.Account{Key: basePubkey, Lamports: 0, Data: make([]byte, 0), Owner: BpfLoaderUpgradeableAddr, Executable: false, RentEpoch: 100}

	assignedPubkey, err := solana.CreateWithSeed(basePubkey, "seed", BpfLoaderUpgradeableAddr)
	assert.NoError(t, err)

	assignedAcct := accounts.Account{Key: assignedPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	assert.NoError(t, err)
	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, assignedAcct, baseAcct})

	acctMetas := []AccountMeta{{Pubkey: assignedAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: baseAcct.Key, IsSigner: false, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	instrWriter := new(bytes.Buffer)
	instrEncoder := bin.NewBinEncoder(instrWriter)
	var assignWithSeed SystemInstrAssignWithSeed
	assignWithSeed.Base = basePubkey
	assignWithSeed.Owner = BpfLoaderUpgradeableAddr
	assignWithSeed.Seed = "seed"
	err = assignWithSeed.MarshalWithEncoder(instrEncoder)
	assert.NoError(t, err)

	instrBytes := instrWriter.Bytes()

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}
