package sealevel

import (
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
	"go.firedancer.io/radiance/pkg/global"
)

const SysvarClockAddrStr = "SysvarC1ock11111111111111111111111111111111"

var SysvarClockAddr = base58.MustDecodeFromString(SysvarClockAddrStr)

const SysvarClockStructLen = 40

type SysvarClock struct {
	Slot                uint64
	EpochStartTimestamp int64
	Epoch               uint64
	LeaderScheduleEpoch uint64
	UnixTimestamp       int64
}

func (sc *SysvarClock) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {
	slot, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read Slot when decoding SysvarClock: %w", err)
	}
	sc.Slot = slot

	epochStartTimestamp, err := decoder.ReadInt64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read EpochStartTimestamp when decoding SysvarClock: %w", err)
	}
	sc.EpochStartTimestamp = epochStartTimestamp

	epoch, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read Epoch when decoding SysvarClock: %w", err)
	}
	sc.Epoch = epoch

	leaderScheduleEpoch, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read LeaderScheduleEpoch when decoding SysvarClock: %w", err)
	}
	sc.LeaderScheduleEpoch = leaderScheduleEpoch

	unixTimestamp, err := decoder.ReadInt64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read UnixTimestamp when decoding SysvarClock: %w", err)
	}
	sc.UnixTimestamp = unixTimestamp
	return
}

func (sc *SysvarClock) MustUnmarshalWithDecoder(decoder *bin.Decoder) {
	err := sc.UnmarshalWithDecoder(decoder)
	if err != nil {
		panic(err.Error())
	}
}

func ReadClockSysvar(accts *accounts.Accounts) SysvarClock {
	clockAccount, err := (*accts).GetAccount(&SysvarClockAddr)
	if err != nil {
		panic("failed to read clock sysvar account")
	}

	dec := bin.NewBinDecoder(clockAccount.Data)

	var clock SysvarClock
	clock.MustUnmarshalWithDecoder(dec)
	return clock
}

func UpdateClockSysvar(globalCtx *global.GlobalCtx) {
	clock := ReadClockSysvar(globalCtx.Accounts)

	// TODO: update clock sysvar logic

	if globalCtx.Bank.Slot != 0 {
	}

	fmt.Printf("updating clock sysvar at slot %d\n", clock.Slot)
}
