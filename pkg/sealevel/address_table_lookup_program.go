package sealevel

import (
	"bytes"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
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

		}

	case AddrTableLookupInstrTypeFreezeLookupTable:
		{

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
