package sealevel

import (
	"bytes"
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
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

func ReadLastRestartSlotSysvar(execCtx *ExecutionCtx) SysvarLastRestartSlot {
	accts := addrObjectForLookup(execCtx)

	lrsAcct, err := (*accts).GetAccount(&SysvarLastRestartSlotAddr)
	if err != nil {
		panic("failed to read LastRestartSlot sysvar account")
	}

	dec := bin.NewBinDecoder(lrsAcct.Data)

	var lrs SysvarLastRestartSlot
	lrs.MustUnmarshalWithDecoder(dec)

	return lrs
}

func WriteLastRestartSlotSysvar(accts *accounts.Accounts, lastRestartSlot SysvarLastRestartSlot) {

	lrsSysvarAcct, err := (*accts).GetAccount(&SysvarLastRestartSlotAddr)
	if err != nil {
		panic("failed to read LastRestartSlot sysvar account")
	}

	data := new(bytes.Buffer)
	enc := bin.NewBinEncoder(data)

	err = enc.WriteUint64(lastRestartSlot.LastRestartSlot, bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize LastRestartSlot for LastRestartSlot sysvar: %w", err)
		panic(err)
	}

	lrsSysvarAcct.Data = data.Bytes()

	err = (*accts).SetAccount(&SysvarLastRestartSlotAddr, lrsSysvarAcct)
	if err != nil {
		err = fmt.Errorf("failed write newly serialized LastRestartSlot sysvar to sysvar account: %w", err)
		panic(err)
	}
}
