package sealevel

import (
	"bytes"
	"fmt"
	"math"
	"math/bits"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
)

const SysvarEpochScheduleAddrStr = "SysvarEpochSchedu1e111111111111111111111111"

var SysvarEpochScheduleAddr = base58.MustDecodeFromString(SysvarEpochScheduleAddrStr)

const SysvarEpochScheduleStructLen = 33

const MinimumSlotsPerEpoch = 32

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

	warmup, err := ReadBool(decoder)
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

func (sr *SysvarEpochSchedule) GetEpoch(slot uint64) uint64 {
	epoch, _ := sr.GetEpochAndSlotIndex(slot)
	return epoch
}

func (sr *SysvarEpochSchedule) GetEpochAndSlotIndex(slot uint64) (uint64, uint64) {
	if slot < sr.FirstNormalSlot {
		nextPowerOfTwo := func(n uint64) uint64 {
			shift := uint64(bits.Len(uint(n)))
			return 1 << shift
		}

		epoch := uint64(bits.TrailingZeros64(nextPowerOfTwo(slot+MinimumSlotsPerEpoch+1)) - bits.TrailingZeros64(MinimumSlotsPerEpoch) - 1)
		epochLen := uint64(math.Pow(2, float64(bits.TrailingZeros64(uint64(epoch+MinimumSlotsPerEpoch)))))
		return epoch, slot - (epochLen - MinimumSlotsPerEpoch)
	} else {
		normalSlotIndex := slot - sr.FirstNormalSlot
		normalEpochIndex := normalSlotIndex / sr.SlotsPerEpoch
		epoch := sr.FirstNormalEpoch + normalEpochIndex
		slotIndex := normalSlotIndex % sr.SlotsPerEpoch
		return epoch, slotIndex
	}
}

func ReadEpochScheduleSysvar(accts *accounts.Accounts) (SysvarEpochSchedule, error) {
	epochScheduleSysvarAcct, err := (*accts).GetAccount(&SysvarEpochScheduleAddr)
	if err != nil {
		return SysvarEpochSchedule{}, InstrErrUnsupportedSysvar
	}

	dec := bin.NewBinDecoder(epochScheduleSysvarAcct.Data)

	var epochSchedule SysvarEpochSchedule
	err = epochSchedule.UnmarshalWithDecoder(dec)

	return epochSchedule, err
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

	epochScheduleSysvarAcct.Data = data.Bytes()

	err = (*accts).SetAccount(&SysvarEpochScheduleAddr, epochScheduleSysvarAcct)
	if err != nil {
		err = fmt.Errorf("failed write newly serialized EpochSchedule sysvar to sysvar account: %w", err)
		panic(err)
	}
}
