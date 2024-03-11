package sealevel

import (
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
	"go.firedancer.io/radiance/pkg/global"
)

const SysvarLastRestartSlotAddrStr = "SysvarLastRestartS1ot1111111111111111111111"

var SysvarLastRestartSlotAddr = base58.MustDecodeFromString(SysvarLastRestartSlotAddrStr)

const SysvarLastRestartSlotStructLen = 8

type SysvarLastRestartSlot struct {
	LastRestartSlot uint64
}

func (lrs *SysvarLastRestartSlot) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {
	lastRestartSlot, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read LastRestartSlot when decoding SysvarLastRestartSlot: %w", err)
	}
	lrs.LastRestartSlot = lastRestartSlot
	return
}

func (sr *SysvarLastRestartSlot) MustUnmarshalWithDecoder(decoder *bin.Decoder) {
	err := sr.UnmarshalWithDecoder(decoder)
	if err != nil {
		panic(err.Error())
	}
}

func ReadLastRestartSlotSysvar(accts *accounts.Accounts) SysvarLastRestartSlot {
	lrsAcct, err := (*accts).GetAccount(&SysvarRentAddr)
	if err != nil {
		panic("failed to read rent sysvar account")
	}

	dec := bin.NewBinDecoder(lrsAcct.Data)

	var lrs SysvarLastRestartSlot
	lrs.MustUnmarshalWithDecoder(dec)

	return lrs
}

// TODO: implement logic for writing the LastRestartSlot sysvar and for creating a default
func UpdateLastRestartSlotSysvar(globalCtx *global.GlobalCtx, newLastRestartSlot *SysvarLastRestartSlot) {

}
