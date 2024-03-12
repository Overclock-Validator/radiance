package sealevel

import (
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
	"go.firedancer.io/radiance/pkg/global"
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

// TODO: implement logic for writing the SlotHistory sysvar and for creating a default
func UpdateSlotHistorySysvar(globalCtx *global.GlobalCtx, newSlotHistory *SysvarSlotHistory) {

}
