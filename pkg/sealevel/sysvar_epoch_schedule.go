package sealevel

import (
	"bytes"
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
)

const SysvarEpochScheduleAddrStr = "SysvarEpochSchedu1e111111111111111111111111"

var SysvarEpochScheduleAddr = base58.MustDecodeFromString(SysvarEpochScheduleAddrStr)

const SysvarEpochScheduleStructLen = 33

type SysvarEpochSchedule struct {
	SlotsPerEpoch            uint64
	LeaderScheduleSlotOffset uint64
	Warmup                   bool
	FirstNormalEpoch         uint64
	FirstNormalSlot          uint64
}

func (ses *SysvarEpochSchedule) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {
	slotsPerEpoch, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read SlotsPerEpoch when decoding SysvarEpochSchedule: %w", err)
	}
	ses.SlotsPerEpoch = slotsPerEpoch

	leaderScheduleSlotOffset, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read LeaderScheduleSlotOffset when decoding SysvarEpochSchedule: %w", err)
	}
	ses.LeaderScheduleSlotOffset = leaderScheduleSlotOffset

	warmup, err := decoder.ReadBool()
	if err != nil {
		return fmt.Errorf("failed to read Warmup when decoding SysvarEpochSchedule: %w", err)
	}
	ses.Warmup = warmup

	firstNormalEpoch, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read FirstNormalEpoch when decoding SysvarEpochSchedule: %w", err)
	}
	ses.FirstNormalEpoch = firstNormalEpoch

	firstNormalSlot, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read FirstNormalSlot when decoding SysvarEpochSchedule: %w", err)
	}
	ses.FirstNormalSlot = firstNormalSlot

	return
}

func (sr *SysvarEpochSchedule) MustUnmarshalWithDecoder(decoder *bin.Decoder) {
	err := sr.UnmarshalWithDecoder(decoder)
	if err != nil {
		panic(err.Error())
	}
}

func ReadEpochScheduleSysvar(accts *accounts.Accounts) SysvarEpochSchedule {
	epochScheduleSysvarAcct, err := (*accts).GetAccount(&SysvarEpochScheduleAddr)
	if err != nil {
		panic("failed to read epoch schedule sysvar account")
	}

	dec := bin.NewBinDecoder(epochScheduleSysvarAcct.Data)

	var epochSchedule SysvarEpochSchedule
	epochSchedule.MustUnmarshalWithDecoder(dec)

	return epochSchedule
}

func WriteEpochScheduleSysvar(accts *accounts.Accounts, epochSchedule SysvarEpochSchedule) {

	epochScheduleSysvarAcct, err := (*accts).GetAccount(&SysvarEpochScheduleAddr)
	if err != nil {
		panic("failed to read EpochSchedule sysvar account")
	}

	data := new(bytes.Buffer)
	enc := bin.NewBinEncoder(data)

	err = enc.WriteUint64(epochSchedule.SlotsPerEpoch, bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize SlotsPerEpoch for EpochSchedule sysvar: %w", err)
		panic(err)
	}

	err = enc.WriteUint64(epochSchedule.LeaderScheduleSlotOffset, bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize LeaderScheduleSlotOffset for EpochSchedule sysvar: %w", err)
		panic(err)
	}

	err = enc.WriteBool(epochSchedule.Warmup)
	if err != nil {
		err = fmt.Errorf("failed to serialize Warmup for EpochSchedule sysvar: %w", err)
		panic(err)
	}

	err = enc.WriteUint64(epochSchedule.FirstNormalEpoch, bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize FirstNormalEpoch for EpochSchedule sysvar: %w", err)
		panic(err)
	}

	err = enc.WriteUint64(epochSchedule.FirstNormalSlot, bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize FirstNormalSlot for EpochSchedule sysvar: %w", err)
		panic(err)
	}

	copy(epochScheduleSysvarAcct.Data, data.Bytes())

	err = (*accts).SetAccount(&SysvarEpochScheduleAddr, epochScheduleSysvarAcct)
	if err != nil {
		err = fmt.Errorf("failed write newly serialized EpochSchedule sysvar to sysvar account: %w", err)
		panic(err)
	}
}
