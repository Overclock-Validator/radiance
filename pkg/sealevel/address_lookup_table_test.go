package sealevel

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/assert"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/cu"
	"go.firedancer.io/radiance/pkg/features"
)

func TestExecute_AddrLookupTable_Program_Test_Create_Lookup_Table_Idempotent(t *testing.T) {

	// system program acct
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	addrLookupTableAddr, bumpSeed, err := solana.FindProgramAddress([][]byte{authorityAcct.Key.Bytes(), recentSlotBytes[:]}, AddressLookupTableAddr)
	assert.NoError(t, err)

	uninitAcct := accounts.Account{Key: addrLookupTableAddr, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// payer acct
	payerPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	payerPubkey := payerPrivateKey.PublicKey()
	payerAcct := accounts.Account{Key: payerPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// system acct
	systemAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 10000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	createLookupTableInstrWriter := new(bytes.Buffer)
	createLookupTableEncoder := bin.NewBinEncoder(createLookupTableInstrWriter)

	var createLookupTable AddrLookupTableInstrCreateLookupTable
	createLookupTable.BumpSeed = bumpSeed
	createLookupTable.RecentSlot = recentSlot

	err = createLookupTable.MarshalWithEncoder(createLookupTableEncoder)
	assert.NoError(t, err)
	instrBytes := createLookupTableInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, uninitAcct, authorityAcct, payerAcct, systemAcct})

	acctMetas := []AccountMeta{{Pubkey: uninitAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: false}, // authority doesn't need to be a signer because relax_authority_signer_check_for_lookup_table_creation is enabled
		{Pubkey: payerAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: systemAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHash := SlotHash{Slot: 123}
	slotHashes = append(slotHashes, slotHash)
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 0
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.NoError(t, err)

	// check that the expected state changes took place upon the address lookup table acct
	addrLookupTablePost, err := txCtx.Accounts.GetAccount(1)
	assert.NoError(t, err)

	assert.Equal(t, AddressLookupTableAddr, addrLookupTablePost.Owner)
	assert.Equal(t, AddressLookupTableMetaSize, len(addrLookupTablePost.Data))
	expectedBalance := rent.MinimumBalance(AddressLookupTableMetaSize)
	assert.Equal(t, expectedBalance, addrLookupTablePost.Lamports)

	acctStatePost, err := unmarshalAddressLookupTable(addrLookupTablePost.Data)
	assert.NoError(t, err)

	assert.Equal(t, uint64(math.MaxUint64), acctStatePost.Meta.DeactivationSlot)
	assert.Equal(t, authorityAcct.Key, *acctStatePost.Meta.Authority)
	assert.Equal(t, uint64(0), acctStatePost.Meta.LastExtendedSlot)
	assert.Equal(t, byte(0), acctStatePost.Meta.LastExtendedSlotStartIndex)
	assert.Equal(t, uint64(0), uint64(len(acctStatePost.Addresses)))
	txCtx.Accounts.Unlock(1)

	// test idempotency by running the exact same instruction again. when the relax_authority_signer_check_for_lookup_table_creation
	// feature is enabled, a CreateLookupTable instruction can be called upon a table acct that already exists so long as
	// the right signer is present.
	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.NoError(t, err)
}

func TestExecute_AddrLookupTable_Program_Test_Create_Lookup_Table_Not_Idempotent(t *testing.T) {

	// system program acct
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	addrLookupTableAddr, bumpSeed, err := solana.FindProgramAddress([][]byte{authorityAcct.Key.Bytes(), recentSlotBytes[:]}, AddressLookupTableAddr)
	assert.NoError(t, err)

	uninitAcct := accounts.Account{Key: addrLookupTableAddr, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// payer acct
	payerPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	payerPubkey := payerPrivateKey.PublicKey()
	payerAcct := accounts.Account{Key: payerPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// system acct
	systemAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 10000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	createLookupTableInstrWriter := new(bytes.Buffer)
	createLookupTableEncoder := bin.NewBinEncoder(createLookupTableInstrWriter)

	var createLookupTable AddrLookupTableInstrCreateLookupTable
	createLookupTable.BumpSeed = bumpSeed
	createLookupTable.RecentSlot = recentSlot

	err = createLookupTable.MarshalWithEncoder(createLookupTableEncoder)
	assert.NoError(t, err)
	instrBytes := createLookupTableInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, uninitAcct, authorityAcct, payerAcct, systemAcct})

	acctMetas := []AccountMeta{{Pubkey: uninitAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false},
		{Pubkey: payerAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: systemAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHash := SlotHash{Slot: 123}
	slotHashes = append(slotHashes, slotHash)
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 0
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.NoError(t, err)

	// check that the expected state changes took place upon the address lookup table acct
	addrLookupTablePost, err := txCtx.Accounts.GetAccount(1)
	assert.NoError(t, err)

	assert.Equal(t, AddressLookupTableAddr, addrLookupTablePost.Owner)
	assert.Equal(t, AddressLookupTableMetaSize, len(addrLookupTablePost.Data))
	expectedBalance := rent.MinimumBalance(AddressLookupTableMetaSize)
	assert.Equal(t, expectedBalance, addrLookupTablePost.Lamports)

	acctStatePost, err := unmarshalAddressLookupTable(addrLookupTablePost.Data)
	assert.NoError(t, err)

	assert.Equal(t, uint64(math.MaxUint64), acctStatePost.Meta.DeactivationSlot)
	assert.Equal(t, authorityAcct.Key, *acctStatePost.Meta.Authority)
	assert.Equal(t, uint64(0), acctStatePost.Meta.LastExtendedSlot)
	assert.Equal(t, byte(0), acctStatePost.Meta.LastExtendedSlotStartIndex)
	assert.Equal(t, uint64(0), uint64(len(acctStatePost.Addresses)))
	txCtx.Accounts.Unlock(1)

	// test idempotency by running the exact same instruction again. when the relax_authority_signer_check_for_lookup_table_creation
	// feature is enabled, a CreateLookupTable instruction can be called upon a table acct that already exists so long as
	// the right signer is present.
	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrAccountAlreadyInitialized, err)
}

func TestExecute_AddrLookupTable_Program_Test_Create_Lookup_Table_Use_Payer_As_Authority(t *testing.T) {

	// system program acct
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	addrLookupTableAddr, bumpSeed, err := solana.FindProgramAddress([][]byte{authorityAcct.Key.Bytes(), recentSlotBytes[:]}, AddressLookupTableAddr)
	assert.NoError(t, err)

	uninitAcct := accounts.Account{Key: addrLookupTableAddr, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// system acct
	systemAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 10000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	createLookupTableInstrWriter := new(bytes.Buffer)
	createLookupTableEncoder := bin.NewBinEncoder(createLookupTableInstrWriter)

	var createLookupTable AddrLookupTableInstrCreateLookupTable
	createLookupTable.BumpSeed = bumpSeed
	createLookupTable.RecentSlot = recentSlot

	err = createLookupTable.MarshalWithEncoder(createLookupTableEncoder)
	assert.NoError(t, err)
	instrBytes := createLookupTableInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, uninitAcct, authorityAcct, systemAcct})

	acctMetas := []AccountMeta{{Pubkey: uninitAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: true}, // authority doesn't need to be a signer because relax_authority_signer_check_for_lookup_table_creation is enabled
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: true},  // use authority as payer as well
		{Pubkey: systemAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHash := SlotHash{Slot: 123}
	slotHashes = append(slotHashes, slotHash)
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 0
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.NoError(t, err)

	// check that the expected state changes took place upon the address lookup table acct
	addrLookupTablePost, err := txCtx.Accounts.GetAccount(1)
	assert.NoError(t, err)

	assert.Equal(t, AddressLookupTableAddr, addrLookupTablePost.Owner)
	assert.Equal(t, AddressLookupTableMetaSize, len(addrLookupTablePost.Data))
	expectedBalance := rent.MinimumBalance(AddressLookupTableMetaSize)
	assert.Equal(t, expectedBalance, addrLookupTablePost.Lamports)

	acctStatePost, err := unmarshalAddressLookupTable(addrLookupTablePost.Data)
	assert.NoError(t, err)

	assert.Equal(t, uint64(math.MaxUint64), acctStatePost.Meta.DeactivationSlot)
	assert.Equal(t, authorityAcct.Key, *acctStatePost.Meta.Authority)
	assert.Equal(t, uint64(0), acctStatePost.Meta.LastExtendedSlot)
	assert.Equal(t, byte(0), acctStatePost.Meta.LastExtendedSlotStartIndex)
	assert.Equal(t, uint64(0), uint64(len(acctStatePost.Addresses)))
	txCtx.Accounts.Unlock(1)
}

func TestExecute_AddrLookupTable_Program_Test_Create_Lookup_Table_Missing_Signer(t *testing.T) {

	// system program acct
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	addrLookupTableAddr, bumpSeed, err := solana.FindProgramAddress([][]byte{authorityAcct.Key.Bytes(), recentSlotBytes[:]}, AddressLookupTableAddr)
	assert.NoError(t, err)

	uninitAcct := accounts.Account{Key: addrLookupTableAddr, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// payer acct
	payerPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	payerPubkey := payerPrivateKey.PublicKey()
	payerAcct := accounts.Account{Key: payerPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// system acct
	systemAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 10000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	createLookupTableInstrWriter := new(bytes.Buffer)
	createLookupTableEncoder := bin.NewBinEncoder(createLookupTableInstrWriter)

	var createLookupTable AddrLookupTableInstrCreateLookupTable
	createLookupTable.BumpSeed = bumpSeed
	createLookupTable.RecentSlot = recentSlot

	err = createLookupTable.MarshalWithEncoder(createLookupTableEncoder)
	assert.NoError(t, err)
	instrBytes := createLookupTableInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, uninitAcct, authorityAcct, payerAcct, systemAcct})

	acctMetas := []AccountMeta{{Pubkey: uninitAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: false},
		{Pubkey: payerAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: systemAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHash := SlotHash{Slot: 123}
	slotHashes = append(slotHashes, slotHash)
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 0
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_AddrLookupTable_Program_Test_Create_Lookup_Table_Not_Recent_Slot(t *testing.T) {

	// system program acct
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	addrLookupTableAddr, bumpSeed, err := solana.FindProgramAddress([][]byte{authorityAcct.Key.Bytes(), recentSlotBytes[:]}, AddressLookupTableAddr)
	assert.NoError(t, err)

	uninitAcct := accounts.Account{Key: addrLookupTableAddr, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// payer acct
	payerPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	payerPubkey := payerPrivateKey.PublicKey()
	payerAcct := accounts.Account{Key: payerPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// system acct
	systemAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 10000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	createLookupTableInstrWriter := new(bytes.Buffer)
	createLookupTableEncoder := bin.NewBinEncoder(createLookupTableInstrWriter)

	var createLookupTable AddrLookupTableInstrCreateLookupTable
	createLookupTable.BumpSeed = bumpSeed
	createLookupTable.RecentSlot = math.MaxUint64 // not a recent slot... should trigger InstrErr::InvalidInstructionData

	err = createLookupTable.MarshalWithEncoder(createLookupTableEncoder)
	assert.NoError(t, err)
	instrBytes := createLookupTableInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, uninitAcct, authorityAcct, payerAcct, systemAcct})

	acctMetas := []AccountMeta{{Pubkey: uninitAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: false}, // authority doesn't need to be a signer because relax_authority_signer_check_for_lookup_table_creation is enabled
		{Pubkey: payerAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: systemAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHash := SlotHash{Slot: 123}
	slotHashes = append(slotHashes, slotHash)
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 0
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidInstructionData, err)
}

func TestExecute_AddrLookupTable_Program_Test_Create_Lookup_Table_PDA_Mismatch(t *testing.T) {

	// system program acct
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	_, bumpSeed, err := solana.FindProgramAddress([][]byte{authorityAcct.Key.Bytes(), recentSlotBytes[:]}, AddressLookupTableAddr)
	assert.NoError(t, err)

	// set the address lookup table address as some random account pubkey rather than a PDA derived from the
	// address table lookup program + authority address. should trigger an InstrErr::InvalidArgument return.
	randomPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	randomPubkey := randomPrivateKey.PublicKey()
	uninitAcct := accounts.Account{Key: randomPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// payer acct
	payerPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	payerPubkey := payerPrivateKey.PublicKey()
	payerAcct := accounts.Account{Key: payerPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// system acct
	systemAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 10000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	createLookupTableInstrWriter := new(bytes.Buffer)
	createLookupTableEncoder := bin.NewBinEncoder(createLookupTableInstrWriter)

	var createLookupTable AddrLookupTableInstrCreateLookupTable
	createLookupTable.BumpSeed = bumpSeed
	createLookupTable.RecentSlot = recentSlot

	err = createLookupTable.MarshalWithEncoder(createLookupTableEncoder)
	assert.NoError(t, err)
	instrBytes := createLookupTableInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, uninitAcct, authorityAcct, payerAcct, systemAcct})

	acctMetas := []AccountMeta{{Pubkey: uninitAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: false}, // authority doesn't need to be a signer because relax_authority_signer_check_for_lookup_table_creation is enabled
		{Pubkey: payerAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: systemAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHash := SlotHash{Slot: 123}
	slotHashes = append(slotHashes, slotHash)
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 0
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidArgument, err)
}

func TestExecute_AddrLookupTable_Program_Test_CloseLookupTable_Success(t *testing.T) {

	// system program acct
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	receiverPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	receiverPubkey := receiverPrivateKey.PublicKey()
	receiverAcct := accounts.Account{Key: receiverPubkey, Lamports: 1, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 4)

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct, receiverAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false},
		{Pubkey: receiverAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.NoError(t, err)

	// check that the lookup table acct has been closed
	tableAcctPost, err := txCtx.Accounts.GetAccount(1)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), uint64(len(tableAcctPost.Data)))
	assert.Equal(t, uint64(0), tableAcctPost.Lamports)

	// ensure that the receiver account got the lamports from the now closed lookup table acct
	receiverAcctPost, err := txCtx.Accounts.GetAccount(3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1338), receiverAcctPost.Lamports)
}

func TestExecute_AddrLookupTable_Program_Test_CloseLookupTable_Table_Not_Deactivated_Failure(t *testing.T) {

	// system program acct
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	receiverPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	receiverPubkey := receiverPrivateKey.PublicKey()
	receiverAcct := accounts.Account{Key: receiverPubkey, Lamports: 1, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // table is activated
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 4)

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct, receiverAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false},
		{Pubkey: receiverAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidArgument, err)
}

func TestExecute_AddrLookupTable_Program_Test_Table_CloseLookupTable_Deactivated_In_Current_Slot_Failure(t *testing.T) {

	// system program acct
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	receiverPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	receiverPubkey := receiverPrivateKey.PublicKey()
	receiverAcct := accounts.Account{Key: receiverPubkey, Lamports: 1, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.Meta.DeactivationSlot = 10 // same as the value we'll set sysvar Clock.slot to below
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 4)

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct, receiverAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false},
		{Pubkey: receiverAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidArgument, err)
}

func TestExecute_AddrLookupTable_Program_Test_Table_CloseLookupTable_Recently_Deactivated_Failure(t *testing.T) {

	// system program acct
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	receiverPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	receiverPubkey := receiverPrivateKey.PublicKey()
	receiverAcct := accounts.Account{Key: receiverPubkey, Lamports: 1, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.Meta.DeactivationSlot = 0
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 4)

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct, receiverAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false},
		{Pubkey: receiverAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	slotHashEntry := SlotHash{Slot: 0}
	slotHashes = append(slotHashes, slotHashEntry)
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidArgument, err)
}

func TestExecute_AddrLookupTable_Program_Test_Table_CloseLookupTable_Immutable_Failure(t *testing.T) {

	// system program acct
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	receiverPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	receiverPubkey := receiverPrivateKey.PublicKey()
	receiverAcct := accounts.Account{Key: receiverPubkey, Lamports: 1, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}
	activatedTableAcct.Data = getBytesForFrozenLookupTable(t)

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 4)

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct, receiverAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false},
		{Pubkey: receiverAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	slotHashEntry := SlotHash{Slot: 0}
	slotHashes = append(slotHashes, slotHashEntry)
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrImmutable, err)
}

func TestExecute_AddrLookupTable_Program_Test_Table_CloseLookupTable_Wrong_Authority_Failure(t *testing.T) {

	// system program acct
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()

	// authority for addr lookup table acct
	wrongAuthorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	wrongAuthorityPubkey := wrongAuthorityPrivateKey.PublicKey()
	wrongAuthorityAcct := accounts.Account{Key: wrongAuthorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	receiverPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	receiverPubkey := receiverPrivateKey.PublicKey()
	receiverAcct := accounts.Account{Key: receiverPubkey, Lamports: 1, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.Meta.DeactivationSlot = 0
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 4) // CloseLookupTable instruction

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, wrongAuthorityAcct, receiverAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: wrongAuthorityAcct.Key, IsSigner: true, IsWritable: false},
		{Pubkey: receiverAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	slotHashEntry := SlotHash{Slot: 0}
	slotHashes = append(slotHashes, slotHashEntry)
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrIncorrectAuthority, err)
}

func TestExecute_AddrLookupTable_Program_Test_CloseLookupTable_Authority_Didnt_Sign_Failure(t *testing.T) {

	// system program acct
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	receiverPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	receiverPubkey := receiverPrivateKey.PublicKey()
	receiverAcct := accounts.Account{Key: receiverPubkey, Lamports: 1, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 4)

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct, receiverAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: false}, // authority didn't sign, so should trigger MissingRequiredSignature
		{Pubkey: receiverAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_AddrLookupTable_Program_Test_DeactivateLookupTable_Success(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 3) // DeactivateLookupTable instruction

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.NoError(t, err)

	// check that the lookup table acct has been closed
	tableAcctPost, err := txCtx.Accounts.GetAccount(1)
	assert.NoError(t, err)

	tableAcctStatePost, err := unmarshalAddressLookupTable(tableAcctPost.Data)
	assert.NoError(t, err)
	// deactivate slot should be clock.Slot, which is 10 as above
	assert.Equal(t, uint64(10), tableAcctStatePost.Meta.DeactivationSlot)

	assert.Equal(t, true, (len(tableAcctPost.Data) >= AddressLookupTableMetaSize))
}

func TestExecute_AddrLookupTable_Program_Test_DeactivateLookupTable_Immutable_Failure(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}
	activatedTableAcct.Data = getBytesForFrozenLookupTable(t)

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 3) // DeactivateLookupTable instruction

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrImmutable, err)
}

func TestExecute_AddrLookupTable_Program_Test_DeactivateLookupTable_Already_Deactivated_Failure(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = 0
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 3) // DeactivateLookupTable instruction

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidArgument, err)
}

func TestExecute_AddrLookupTable_Program_Test_DeactivateLookupTable_Wrong_Authority_Failure(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()

	// authority for addr lookup table acct
	wrongAuthorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	wrongAuthorityPubkey := wrongAuthorityPrivateKey.PublicKey()
	wrongAuthorityAcct := accounts.Account{Key: wrongAuthorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 3) // DeactivateLookupTable instruction

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, wrongAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: wrongAuthorityAcct.Key, IsSigner: true, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrIncorrectAuthority, err)
}

func TestExecute_AddrLookupTable_Program_Test_DeactivateLookupTable_Authority_Didnt_Sign(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 3) // DeactivateLookupTable instruction

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_AddrLookupTable_Program_Test_FreezeLookupTable_Success(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	lookupTable.Addresses = append(lookupTable.Addresses, SystemProgramAddr)
	lookupTable.Addresses = append(lookupTable.Addresses, VoteProgramAddr)
	lookupTable.Addresses = append(lookupTable.Addresses, StakeProgramAddr)
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 1)

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.NoError(t, err)

	// check that the lookup table acct has been closed
	tableAcctPost, err := txCtx.Accounts.GetAccount(1)
	assert.NoError(t, err)

	tableAcctStatePost, err := unmarshalAddressLookupTable(tableAcctPost.Data)
	assert.NoError(t, err)
	isNil := tableAcctStatePost.Meta.Authority == nil
	assert.Equal(t, true, isNil)
}

func getBytesForFrozenLookupTable(t *testing.T) []byte {
	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	lookupTable.Addresses = append(lookupTable.Addresses, SystemProgramAddr)
	lookupTable.Addresses = append(lookupTable.Addresses, VoteProgramAddr)
	lookupTable.Addresses = append(lookupTable.Addresses, StakeProgramAddr)
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, AddrLookupTableInstrTypeFreezeLookupTable)

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.NoError(t, err)

	// check that the lookup table acct has been closed
	tableAcctPost, err := txCtx.Accounts.GetAccount(1)
	assert.NoError(t, err)

	tableAcctStatePost, err := unmarshalAddressLookupTable(tableAcctPost.Data)
	assert.NoError(t, err)
	isNil := tableAcctStatePost.Meta.Authority == nil
	assert.Equal(t, true, isNil)

	return tableAcctPost.Data
}

func TestExecute_AddrLookupTable_Program_Test_FreezeLookupTable_Immutable_Failure(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}
	activatedTableAcct.Data = getBytesForFrozenLookupTable(t)

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 1)

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrImmutable, err)
}

func TestExecute_AddrLookupTable_Program_Test_FreezeLookupTable_Deactivated_Failure(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = 0 // already deactivated
	lookupTable.Addresses = append(lookupTable.Addresses, SystemProgramAddr)
	lookupTable.Addresses = append(lookupTable.Addresses, VoteProgramAddr)
	lookupTable.Addresses = append(lookupTable.Addresses, StakeProgramAddr)
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 1)

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidArgument, err)
}

func TestExecute_AddrLookupTable_Program_Test_FreezeLookupTable_Wrong_Authority_Failure(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()

	// authority for addr lookup table acct
	wrongAuthorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	wrongAuthorityPubkey := wrongAuthorityPrivateKey.PublicKey()
	wrongAuthorityAcct := accounts.Account{Key: wrongAuthorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	lookupTable.Addresses = append(lookupTable.Addresses, SystemProgramAddr)
	lookupTable.Addresses = append(lookupTable.Addresses, VoteProgramAddr)
	lookupTable.Addresses = append(lookupTable.Addresses, StakeProgramAddr)
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 1)

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, wrongAuthorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: wrongAuthorityAcct.Key, IsSigner: true, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrIncorrectAuthority, err)
}

func TestExecute_AddrLookupTable_Program_Test_FreezeLookupTable_Authority_Didnt_Sign(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	lookupTable.Addresses = append(lookupTable.Addresses, SystemProgramAddr)
	lookupTable.Addresses = append(lookupTable.Addresses, VoteProgramAddr)
	lookupTable.Addresses = append(lookupTable.Addresses, StakeProgramAddr)
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 1)

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_AddrLookupTable_Program_Test_FreezeLookupTable_Empty_Table_Failure(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 1337, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	instrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(instrBytes, 1)

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidInstructionData, err)
}

func TestExecute_AddrLookupTable_Program_Test_ExtendLookupTable_Success(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 0, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	payerPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	payerPubkey := payerPrivateKey.PublicKey()
	payerAcct := accounts.Account{Key: payerPubkey, Lamports: 10000000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 10000000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: true, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	var extend AddrLookupTableInstrExtendLookupTable
	extend.NewAddresses = append(extend.NewAddresses, SystemProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, VoteProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, StakeProgramAddr)
	writer := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(writer)
	err = extend.MarshalWithEncoder(encoder)
	assert.NoError(t, err)

	instrBytes := writer.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct, payerAcct, systemProgramAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false},
		{Pubkey: payerAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: systemProgramAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.NoError(t, err)

	// check that the lookup table acct has been closed
	tableAcctPost, err := txCtx.Accounts.GetAccount(1)
	assert.NoError(t, err)

	tableAcctStatePost, err := unmarshalAddressLookupTable(tableAcctPost.Data)
	assert.NoError(t, err)

	// check that three accounts were added to the lookup table
	assert.Equal(t, int(3), len(tableAcctStatePost.Addresses))

	// check that the newly added account keys are as expected
	assert.Equal(t, solana.PublicKeyFromBytes(SystemProgramAddr[:]), tableAcctStatePost.Addresses[0])
	assert.Equal(t, solana.PublicKeyFromBytes(VoteProgramAddr[:]), tableAcctStatePost.Addresses[1])
	assert.Equal(t, solana.PublicKeyFromBytes(StakeProgramAddr[:]), tableAcctStatePost.Addresses[2])
}

func TestExecute_AddrLookupTable_Program_Test_ExtendLookupTable_Wrong_Authority_Failure(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()

	// authority for addr lookup table acct
	wrongAuthorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	wrongAuthorityPubkey := wrongAuthorityPrivateKey.PublicKey()
	wrongAuthorityAcct := accounts.Account{Key: wrongAuthorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 0, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	payerPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	payerPubkey := payerPrivateKey.PublicKey()
	payerAcct := accounts.Account{Key: payerPubkey, Lamports: 10000000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 10000000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: true, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	var extend AddrLookupTableInstrExtendLookupTable
	extend.NewAddresses = append(extend.NewAddresses, SystemProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, VoteProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, StakeProgramAddr)
	writer := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(writer)
	err = extend.MarshalWithEncoder(encoder)
	assert.NoError(t, err)

	instrBytes := writer.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, wrongAuthorityAcct, payerAcct, systemProgramAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: wrongAuthorityAcct.Key, IsSigner: true, IsWritable: false},
		{Pubkey: payerAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: systemProgramAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrIncorrectAuthority, err)
}

func TestExecute_AddrLookupTable_Program_Test_ExtendLookupTable_Authority_Didnt_Sign_Failure(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 0, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	payerPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	payerPubkey := payerPrivateKey.PublicKey()
	payerAcct := accounts.Account{Key: payerPubkey, Lamports: 10000000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 10000000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: true, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	var extend AddrLookupTableInstrExtendLookupTable
	extend.NewAddresses = append(extend.NewAddresses, SystemProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, VoteProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, StakeProgramAddr)
	writer := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(writer)
	err = extend.MarshalWithEncoder(encoder)
	assert.NoError(t, err)

	instrBytes := writer.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct, payerAcct, systemProgramAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: false, IsWritable: false},
		{Pubkey: payerAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: systemProgramAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrMissingRequiredSignature, err)
}

func TestExecute_AddrLookupTable_Program_Test_ExtendLookupTable_Deactivated_Table_Failure(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 0, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	payerPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	payerPubkey := payerPrivateKey.PublicKey()
	payerAcct := accounts.Account{Key: payerPubkey, Lamports: 10000000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 10000000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: true, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = 0 // table is deactivated
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	var extend AddrLookupTableInstrExtendLookupTable
	extend.NewAddresses = append(extend.NewAddresses, SystemProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, VoteProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, StakeProgramAddr)
	writer := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(writer)
	err = extend.MarshalWithEncoder(encoder)
	assert.NoError(t, err)

	instrBytes := writer.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct, payerAcct, systemProgramAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false},
		{Pubkey: payerAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: systemProgramAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidArgument, err)
}

func TestExecute_AddrLookupTable_Program_Test_ExtendLookupTable_Immutable_Failure(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 0, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}
	activatedTableAcct.Data = getBytesForFrozenLookupTable(t)

	payerPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	payerPubkey := payerPrivateKey.PublicKey()
	payerAcct := accounts.Account{Key: payerPubkey, Lamports: 10000000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 10000000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: true, RentEpoch: 100}

	var extend AddrLookupTableInstrExtendLookupTable
	extend.NewAddresses = append(extend.NewAddresses, SystemProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, VoteProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, StakeProgramAddr)
	writer := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(writer)
	err = extend.MarshalWithEncoder(encoder)
	assert.NoError(t, err)

	instrBytes := writer.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct, payerAcct, systemProgramAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false},
		{Pubkey: payerAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: systemProgramAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrImmutable, err)
}

func TestExecute_AddrLookupTable_Program_Test_ExtendLookupTable_Didnt_Include_Payer(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 0, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	var extend AddrLookupTableInstrExtendLookupTable
	extend.NewAddresses = append(extend.NewAddresses, SystemProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, VoteProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, StakeProgramAddr)
	writer := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(writer)
	err = extend.MarshalWithEncoder(encoder)
	assert.NoError(t, err)

	instrBytes := writer.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrNotEnoughAccountKeys, err)
}

func TestExecute_AddrLookupTable_Program_Test_ExtendLookupTable_Didnt_Include_Payer_But_Prepaid_Success(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 10000000, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	var extend AddrLookupTableInstrExtendLookupTable
	extend.NewAddresses = append(extend.NewAddresses, SystemProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, VoteProgramAddr)
	extend.NewAddresses = append(extend.NewAddresses, StakeProgramAddr)
	writer := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(writer)
	err = extend.MarshalWithEncoder(encoder)
	assert.NoError(t, err)

	instrBytes := writer.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.NoError(t, err)
}

func TestExecute_AddrLookupTable_Program_Test_ExtendLookupTable_Too_Many_Addresses_Failure(t *testing.T) {

	lookupTableProgramAcct := accounts.Account{Key: AddressLookupTableAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// authority for addr lookup table acct
	authorityPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	authorityPubkey := authorityPrivateKey.PublicKey()
	authorityAcct := accounts.Account{Key: authorityPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	recentSlot := uint64(123)
	var recentSlotBytes [8]byte
	binary.LittleEndian.PutUint64(recentSlotBytes[:], recentSlot)

	activatedTablePrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	activatedTablePubkey := activatedTablePrivateKey.PublicKey()
	activatedTableAcct := accounts.Account{Key: activatedTablePubkey, Lamports: 0, Data: make([]byte, 0), Owner: AddressLookupTableAddr, Executable: false, RentEpoch: 100}

	payerPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	payerPubkey := payerPrivateKey.PublicKey()
	payerAcct := accounts.Account{Key: payerPubkey, Lamports: 10000000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 10000000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: true, RentEpoch: 100}

	var lookupTable AddressLookupTable
	lookupTable.Meta.Authority = &authorityPubkey
	lookupTable.State = AddressLookupTableProgramStateLookupTable
	lookupTable.Meta.DeactivationSlot = math.MaxUint64 // denotes an active address lookup table
	for count := 0; count < 256; count++ {             // fill lookup table with addresses up to the max number, 256
		lookupTable.Addresses = append(lookupTable.Addresses, SystemProgramAddr)
	}
	addrLookupTableBytes, err := marshalAddressLookupTable(&lookupTable)
	assert.NoError(t, err)
	activatedTableAcct.Data = addrLookupTableBytes

	var extend AddrLookupTableInstrExtendLookupTable
	extend.NewAddresses = append(extend.NewAddresses, SystemProgramAddr) // trying to add one more to the table should cause an error
	writer := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(writer)
	err = extend.MarshalWithEncoder(encoder)
	assert.NoError(t, err)

	instrBytes := writer.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{lookupTableProgramAcct, activatedTableAcct, authorityAcct, payerAcct, systemProgramAcct})

	acctMetas := []AccountMeta{{Pubkey: activatedTableAcct.Key, IsSigner: false, IsWritable: true},
		{Pubkey: authorityAcct.Key, IsSigner: true, IsWritable: false},
		{Pubkey: payerAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: systemProgramAcct.Key, IsSigner: false, IsWritable: false}}

	instructionAccts := InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}
	f := features.NewFeaturesDefault()
	f.EnableFeature(features.RelaxAuthoritySignerCheckForLookupTableCreation, 0)
	execCtx.GlobalCtx.Features = *f

	execCtx.Accounts = accounts.NewMemAccounts()

	var slotHashes SysvarSlotHashes
	slotHashesAcct := accounts.Account{}
	slotHashesAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarSlotHashesAddr, &slotHashesAcct)
	WriteSlotHashesSysvar(&execCtx.Accounts, slotHashes)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0
	rentAcct := accounts.Account{}
	rentAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	var clock SysvarClock
	clock.Slot = 10
	clockAcct := accounts.Account{}
	clockAcct.Lamports = 1
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.Equal(t, InstrErrInvalidArgument, err)
}
