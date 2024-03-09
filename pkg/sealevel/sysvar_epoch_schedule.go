package sealevel

import (
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
	"go.firedancer.io/radiance/pkg/global"
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

// TODO: implement logic for writing the epoch schedule sysvar and for creating a default
func UpdateEpochScheduleSysvar(globalCtx *global.GlobalCtx, newEpochSchedule *SysvarEpochSchedule) {

}
