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

func (createLookupTable *AddrLookupTableInstrCreateLookupTable) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	createLookupTable.RecentSlot, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	createLookupTable.BumpSeed, err = decoder.ReadByte()
	return err
}

type AddrLookupTableInstrExtendLookupTable struct {
	NewAddresses []solana.PublicKey
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
