package sealevel

import (
	"bytes"
	"encoding/binary"
	"math"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/safemath"
	"k8s.io/klog/v2"
)

const (
	AddrTableLookupInstrTypeCreateLookupTable = iota
	AddrTableLookupInstrTypeFreezeLookupTable
	AddrTableLookupInstrTypeExtendLookupTable
	AddrTableLookupInstrTypeDeactivateLookupTable
	AddrTableLookupInstrTypeCloseLookupTable
)

type AddrLookupTableInstrCreateLookupTable struct {
	RecentSlot uint64
	BumpSeed   byte
}

type AddrLookupTableInstrExtendLookupTable struct {
	NewAddresses []solana.PublicKey
}

const (
	AddressLookupTableStateUninitialized = iota
	AddressLookupTableStateLookupTable
)

const AddressLookupTableMetaSize = 56

type LookupTableMeta struct {
	DeactivationSlot           uint64
	LastExtendedSlot           uint64
	LastExtendedSlotStartIndex byte
	Authority                  *solana.PublicKey
	Padding                    uint16
}

type AddressLookupTable struct {
	State     uint32
	Meta      LookupTableMeta
	Addresses []solana.PublicKey
}

func (createLookupTable *AddrLookupTableInstrCreateLookupTable) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	createLookupTable.RecentSlot, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	createLookupTable.BumpSeed, err = decoder.ReadByte()
	return err
}

func (extendLookupTable *AddrLookupTableInstrExtendLookupTable) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	size, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	for count := uint64(0); count < size; count++ {
		pkBytes, err := decoder.ReadBytes(solana.PublicKeyLength)
		if err != nil {
			return err
		}
		pk := solana.PublicKeyFromBytes(pkBytes)
		extendLookupTable.NewAddresses = append(extendLookupTable.NewAddresses, pk)
	}

	return nil
}

func (lookupTableMeta *LookupTableMeta) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error

	lookupTableMeta.DeactivationSlot, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	lookupTableMeta.LastExtendedSlot, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	lookupTableMeta.LastExtendedSlotStartIndex, err = decoder.ReadByte()
	if err != nil {
		return err
	}

	hasAuthority, err := decoder.ReadBool()
	if err != nil {
		return err
	}

	if hasAuthority {
		authorityBytes, err := decoder.ReadBytes(solana.PublicKeyLength)
		if err != nil {
			return err
		}

		authorityPk := solana.PublicKeyFromBytes(authorityBytes)
		lookupTableMeta.Authority = authorityPk.ToPointer()
	}

	lookupTableMeta.Padding, err = decoder.ReadUint16(bin.LE)
	return err
}

func (lookupTableMeta *LookupTableMeta) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint64(lookupTableMeta.DeactivationSlot, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(lookupTableMeta.LastExtendedSlot, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteByte(lookupTableMeta.LastExtendedSlotStartIndex)
	if err != nil {
		return err
	}

	if lookupTableMeta.Authority != nil {
		err = encoder.WriteBool(true)
		if err != nil {
			return err
		}
		authority := *lookupTableMeta.Authority
		err = encoder.WriteBytes(authority[:], false)
		if err != nil {
			return err
		}
	} else {
		err = encoder.WriteBool(false)
		if err != nil {
			return err
		}
	}

	err = encoder.WriteUint16(lookupTableMeta.Padding, bin.LE)
	return err
}

func unmarshalAddressLookupTable(data []byte) (*AddressLookupTable, error) {
	addrLookupTable := new(AddressLookupTable)
	decoder := bin.NewBinDecoder(data)

	state, err := decoder.ReadUint32(bin.LE)
	if err != nil {
		return nil, InstrErrInvalidAccountData
	}

	if state != AddressLookupTableStateLookupTable && state != AddressLookupTableStateUninitialized {
		return nil, InstrErrInvalidAccountData
	}

	err = addrLookupTable.Meta.UnmarshalWithDecoder(decoder)
	if err != nil {
		return nil, InstrErrInvalidAccountData
	}

	if state == AddressLookupTableStateUninitialized {
		return nil, InstrErrUninitializedAccount
	}

	addrLookupTable.State = AddressLookupTableStateLookupTable

	if len(data) < AddressLookupTableMetaSize {
		return nil, InstrErrInvalidAccountData
	}

	rawAddrData := data[AddressLookupTableMetaSize:]
	rawAddrDataLen := len(rawAddrData)

	if rawAddrDataLen == 0 || (rawAddrDataLen%solana.PublicKeyLength) != 0 {
		return nil, InstrErrInvalidAccountData
	}

	var addrs []solana.PublicKey

	for pos := 0; pos < len(rawAddrData); pos += solana.PublicKeyLength {
		pkBytes := rawAddrData[pos : pos+solana.PublicKeyLength]
		pk := solana.PublicKeyFromBytes(pkBytes)
		addrs = append(addrs, pk)
	}

	addrLookupTable.Addresses = addrs

	return addrLookupTable, nil
}

func marshalAddressLookupTable(addrLookupTable *AddressLookupTable) ([]byte, error) {
	buffer := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(buffer)

	err := encoder.WriteUint32(addrLookupTable.State, bin.LE)
	if err != nil {
		return nil, err
	}

	// nothing else to serialize up for an uninitialized account state
	if addrLookupTable.State == AddressLookupTableStateUninitialized {
		return buffer.Bytes(), nil
	}

	err = addrLookupTable.Meta.MarshalWithEncoder(encoder)
	if err != nil {
		return nil, err
	}

	for _, addr := range addrLookupTable.Addresses {
		pkBytes := addr[:]
		err = encoder.WriteBytes(pkBytes, false)
		if err != nil {
			return nil, err
		}
	}

	return buffer.Bytes(), nil
}

func AddressTableLookupExecute(execCtx *ExecutionCtx) error {
	err := execCtx.ComputeMeter.Consume(CUAddressTableLookupDefaultComputeUnits)
	if err != nil {
		return err
	}

	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	instrData := instrCtx.Data

	decoder := bin.NewBinDecoder(instrData)
	instructionType, err := decoder.ReadUint32(bin.LE)
	if err != nil {
		return InstrErrInvalidInstructionData
	}

	switch instructionType {
	case AddrTableLookupInstrTypeCreateLookupTable:
		{
			var createLookupTable AddrLookupTableInstrCreateLookupTable
			err = createLookupTable.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}

			err = AddressTableLookupCreateLookupTable(execCtx, createLookupTable.RecentSlot, createLookupTable.BumpSeed)
		}

	case AddrTableLookupInstrTypeFreezeLookupTable:
		{
			err = AddressTableLookupFreezeLookupTable(execCtx)
		}

	case AddrTableLookupInstrTypeExtendLookupTable:
		{

		}

	case AddrTableLookupInstrTypeDeactivateLookupTable:
		{

		}

	case AddrTableLookupInstrTypeCloseLookupTable:
		{

		}

	default:
		{
			err = InstrErrInvalidInstructionData
		}
	}

	return err
}

func setAddrTableLookupAccountState(acct *BorrowedAccount, state *AddressLookupTable, f features.Features) error {
	acctStateBytes, err := marshalAddressLookupTable(state)
	if err != nil {
		return err
	}

	err = acct.SetState(f, acctStateBytes)
	return err
}

func AddressTableLookupCreateLookupTable(execCtx *ExecutionCtx, untrustedRecentSlot uint64, bumpSeed byte) error {
	txCtx := execCtx.TransactionContext

	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	lookupTableAcct, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}

	lookupTableLamports := lookupTableAcct.Lamports()
	tableKey := lookupTableAcct.Key()
	lookupTableOwner := lookupTableAcct.Owner()

	if !execCtx.GlobalCtx.Features.IsActive(features.RelaxAuthoritySignerCheckForLookupTableCreation) &&
		len(lookupTableAcct.Data()) != 0 {
		return InstrErrAccountAlreadyInitialized
	}

	lookupTableAcct.DropBorrow()

	authorityAcct, err := instrCtx.BorrowInstructionAccount(txCtx, 1)
	if err != nil {
		return err
	}
	authorityKey := authorityAcct.Key()

	if !execCtx.GlobalCtx.Features.IsActive(features.RelaxAuthoritySignerCheckForLookupTableCreation) &&
		!authorityAcct.IsSigner() {
		return InstrErrMissingRequiredSignature
	}

	authorityAcct.DropBorrow()

	payerAcct, err := instrCtx.BorrowInstructionAccount(txCtx, 2)
	if err != nil {
		return err
	}
	payerKey := payerAcct.Key()

	if !payerAcct.IsSigner() {
		return InstrErrMissingRequiredSignature
	}

	payerAcct.DropBorrow()

	slotHashes := ReadSlotHashesSysvar(&execCtx.Accounts)
	_, err = slotHashes.Get(untrustedRecentSlot)
	if err != nil {
		return InstrErrInvalidInstructionData
	}

	derivationSlot := untrustedRecentSlot

	var seeds [][]byte
	seeds = append(seeds, authorityKey[:])
	derivationSlotBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(derivationSlotBytes, derivationSlot)
	seeds = append(seeds, derivationSlotBytes)
	seeds = append(seeds, []byte{bumpSeed})

	derivedTableKey, err := solana.CreateProgramAddress(seeds, AddressLookupTableAddr)
	if err != nil {
		return err
	}

	if tableKey != derivedTableKey {
		klog.Infof("Table address must match derived address: %s", derivedTableKey)
		return InstrErrInvalidArgument
	}

	if execCtx.GlobalCtx.Features.IsActive(features.RelaxAuthoritySignerCheckForLookupTableCreation) &&
		lookupTableOwner == AddressLookupTableAddr {
		return nil
	}

	tableAcctDataLen := uint64(AddressLookupTableMetaSize)
	rent := ReadRentSysvar(&execCtx.Accounts)

	minBalance := rent.MinimumBalance(tableAcctDataLen)
	if minBalance > 1 {
		minBalance = 1
	}
	requiredLamports := safemath.SaturatingSubU64(minBalance, lookupTableLamports)

	if requiredLamports > 0 {
		txInstr := newTransferInstruction(payerKey, tableKey, requiredLamports)
		err = execCtx.NativeInvoke(*txInstr, []solana.PublicKey{payerKey})
		if err != nil {
			return err
		}
	}

	allocInstr := newAllocateInstruction(tableKey, tableAcctDataLen)
	err = execCtx.NativeInvoke(*allocInstr, []solana.PublicKey{tableKey})
	if err != nil {
		return err
	}

	assignInstr := newAssignInstruction(tableKey, AddressLookupTableAddr)
	err = execCtx.NativeInvoke(*assignInstr, []solana.PublicKey{tableKey})
	if err != nil {
		return err
	}

	lookupTableAcct, err = instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}

	newState := &AddressLookupTable{State: AddressLookupTableStateLookupTable, Meta: LookupTableMeta{Authority: &authorityKey}}
	err = setAddrTableLookupAccountState(lookupTableAcct, newState, execCtx.GlobalCtx.Features)
	return err
}

func AddressTableLookupFreezeLookupTable(execCtx *ExecutionCtx) error {
	txCtx := execCtx.TransactionContext

	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	lookupTableAcct, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}

	if lookupTableAcct.Owner() != AddressLookupTableAddr {
		return InstrErrInvalidAccountOwner
	}

	lookupTableAcct.DropBorrow()

	authorityAcct, err := instrCtx.BorrowInstructionAccount(txCtx, 1)
	if err != nil {
		return err
	}
	authorityKey := authorityAcct.Key()

	if !execCtx.GlobalCtx.Features.IsActive(features.RelaxAuthoritySignerCheckForLookupTableCreation) &&
		!authorityAcct.IsSigner() {
		return InstrErrMissingRequiredSignature
	}

	authorityAcct.DropBorrow()

	lookupTableAcct, err = instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}

	lookupTableData := lookupTableAcct.Data()
	lookupTable, err := unmarshalAddressLookupTable(lookupTableData)
	if err != nil {
		return InstrErrInvalidAccountData
	}

	if lookupTable.Meta.Authority == nil {
		klog.Infof("lookup table is already frozen")
		return InstrErrImmutable
	}

	if *lookupTable.Meta.Authority != authorityKey {
		return InstrErrIncorrectAuthority
	}

	if lookupTable.Meta.DeactivationSlot != math.MaxUint64 {
		klog.Infof("Deactivated tables cannot be frozen")
		return InstrErrInvalidArgument
	}

	if len(lookupTable.Addresses) == 0 {
		klog.Infof("Empty lookup tables cannot be frozen")
		return InstrErrInvalidInstructionData
	}

	lookupTable.Meta.Authority = nil
	err = setAddrTableLookupAccountState(lookupTableAcct, lookupTable, execCtx.GlobalCtx.Features)

	return err
}
