package sealevel

import (
	"bytes"
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
)

const SysvarSlotHistoryAddrStr = "SysvarS1otHistory11111111111111111111111111"

var SysvarSlotHistoryAddr = base58.MustDecodeFromString(SysvarSlotHistoryAddrStr)

type SlotHistoryInner struct {
	BlocksLen uint64
	Blocks    []uint64
}

type SlotHistoryBitvec struct {
	Bits SlotHistoryInner
	Len  uint64
}

type SysvarSlotHistory struct {
	Bits     SlotHistoryBitvec
	NextSlot uint64
}

func (sh *SysvarSlotHistory) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {

	opt, err := decoder.ReadByte()

	if opt != 0 {
		sh.Bits.Bits.BlocksLen, err = decoder.ReadUint64(bin.LE)
		if err != nil {
			return fmt.Errorf("failed to read BlocksLen when decoding SysvarSlotHistory: %w", err)
		}

		for count := 0; count < int(sh.Bits.Bits.BlocksLen); count++ {
			block, err := decoder.ReadUint64(bin.LE)
			if err != nil {
				return fmt.Errorf("failed to read a block when decoding Bitvec in SysvarSlotHistory: %w", err)
			}
			sh.Bits.Bits.Blocks = append(sh.Bits.Bits.Blocks, block)
		}
	}

	sh.Bits.Len, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read Len when decoding Bitvec in SysvarSlotHistory: %w", err)
	}

	sh.NextSlot, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read NextSlot when decoding SysvarSlotHistory: %w", err)
	}

	return
}

func (sr *SysvarSlotHistory) MustUnmarshalWithDecoder(decoder *bin.Decoder) {
	err := sr.UnmarshalWithDecoder(decoder)
	if err != nil {
		panic(err.Error())
	}
}

func ReadSlotHistorySysvar(accts *accounts.Accounts) SysvarSlotHistory {
	slotHistorySysvarAcct, err := (*accts).GetAccount(&SysvarSlotHistoryAddr)
	if err != nil {
		panic("failed to read SlotHistory sysvar account")
	}

	dec := bin.NewBinDecoder(slotHistorySysvarAcct.Data)

	var slotHistory SysvarSlotHistory
	slotHistory.MustUnmarshalWithDecoder(dec)

	return slotHistory
}

func WriteSlotHistorySysvar(accts *accounts.Accounts, slotHistory SysvarSlotHistory) {

	slotHistorySysvarAcct, err := (*accts).GetAccount(&SysvarSlotHistoryAddr)
	if err != nil {
		panic("failed to read EpochRewards sysvar account")
	}

	data := new(bytes.Buffer)
	enc := bin.NewBinEncoder(data)

	if slotHistory.Bits.Bits.BlocksLen != 0 {
		err = enc.WriteByte(1)
		if err != nil {
			err = fmt.Errorf("failed to serialize opt byte for SlotHistory sysvar: %w", err)
			panic(err)
		}

		err = enc.WriteUint64(slotHistory.Bits.Bits.BlocksLen, bin.LE)
		if err != nil {
			err = fmt.Errorf("failed to serialize BlocksLen for SlotHistory sysvar: %w", err)
			panic(err)
		}

		for count := 0; count < int(slotHistory.Bits.Bits.BlocksLen); count++ {
			err = enc.WriteUint64(slotHistory.Bits.Bits.Blocks[count], bin.LE)
			if err != nil {
				err = fmt.Errorf("failed to serialize a Block for SlotHistory sysvar: %w", err)
				panic(err)
			}
		}
	} else {
		err = enc.WriteByte(0)
		if err != nil {
			err = fmt.Errorf("failed to serialize opt byte for SlotHistory sysvar: %w", err)
			panic(err)
		}
	}

	err = enc.WriteUint64(slotHistory.Bits.Len, bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize Bits.Len for SlotHistory sysvar: %w", err)
		panic(err)
	}

	err = enc.WriteUint64(slotHistory.NextSlot, bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize NextSlot for SlotHistory sysvar: %w", err)
		panic(err)
	}

	slotHistorySysvarAcct.Data = data.Bytes()

	err = (*accts).SetAccount(&SysvarSlotHistoryAddr, slotHistorySysvarAcct)
	if err != nil {
		err = fmt.Errorf("failed to write newly serialized SlotHistory sysvar to sysvar account: %w", err)
		panic(err)
	}
}
