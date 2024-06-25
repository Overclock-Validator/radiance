package sealevel

import (
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

type LookupTableMeta struct {
	DeactivationSlot           uint64
	LastExtendedSlot           uint64
	LastExtendedSlotStartIndex byte
	Authority                  *solana.PublicKey
	Padding                    uint16
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
