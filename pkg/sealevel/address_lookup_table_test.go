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
