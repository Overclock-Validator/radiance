package sealevel

import (
	"bytes"
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
)

const SysvarEpochRewardsAddrStr = "SysvarEpochRewards1111111111111111111111111"

var SysvarEpochRewardsAddr = base58.MustDecodeFromString(SysvarEpochRewardsAddrStr)

const SysvarEpochRewardsStructLen = 81

type SysvarEpochRewards struct {
	DistributionStartingBlockHeight uint64
	NumPartitions                   uint64
	ParentBlockhash                 [32]byte
	TotalPoints                     bin.Uint128
	TotalRewards                    uint64
	DistributedRewards              uint64
	Active                          bool
}

func (ser *SysvarEpochRewards) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error

	ser.DistributionStartingBlockHeight, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read DistributionStartingBlockHeight when decoding SysvarEpochRewards: %w", err)
	}

	ser.NumPartitions, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read NumPartitions when decoding SysvarEpochRewards: %w", err)
	}

	parentBlockhash, err := decoder.ReadBytes(32)
	if err != nil {
		return fmt.Errorf("failed to read ParentBlockhash when decoding SysvarEpochRewards: %w", err)
	}
	copy(ser.ParentBlockhash[:], parentBlockhash)

	ser.TotalPoints, err = decoder.ReadUint128(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read TotalPoints when decoding SysvarEpochRewards: %w", err)
	}

	ser.TotalRewards, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read TotalRewards when decoding SysvarEpochRewards: %w", err)
	}

	ser.DistributedRewards, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read DistributedRewards when decoding SysvarEpochRewards: %w", err)
	}

	ser.Active, err = decoder.ReadBool()
	return err
}

func (ser *SysvarEpochRewards) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint64(ser.DistributionStartingBlockHeight, bin.LE)
	if err != nil {
		return fmt.Errorf("failed to write DistributionStartingBlockHeight when decoding SysvarEpochRewards: %w", err)
	}

	err = encoder.WriteUint64(ser.NumPartitions, bin.LE)
	if err != nil {
		return fmt.Errorf("failed to write NumPartitions when decoding SysvarEpochRewards: %w", err)
	}

	err = encoder.WriteBytes(ser.ParentBlockhash[:], false)
	if err != nil {
		return fmt.Errorf("failed to write ParentBlockhash when decoding SysvarEpochRewards: %w", err)
	}

	err = encoder.WriteUint128(ser.TotalPoints, bin.LE)
	if err != nil {
		return fmt.Errorf("failed to write TotalPoints when decoding SysvarEpochRewards: %w", err)
	}

	err = encoder.WriteUint64(ser.TotalRewards, bin.LE)
	if err != nil {
		return fmt.Errorf("failed to write TotalRewards when decoding SysvarEpochRewards: %w", err)
	}

	err = encoder.WriteUint64(ser.DistributedRewards, bin.LE)
	if err != nil {
		return fmt.Errorf("failed to write DistributedRewards when decoding SysvarEpochRewards: %w", err)
	}

	err = encoder.WriteBool(ser.Active)
	return err
}

func (sr *SysvarEpochRewards) MustUnmarshalWithDecoder(decoder *bin.Decoder) {
	err := sr.UnmarshalWithDecoder(decoder)
	if err != nil {
		panic(err.Error())
	}
}

func ReadEpochRewardsSysvar(execCtx *ExecutionCtx) (SysvarEpochRewards, error) {
	accts := addrObjectForLookup(execCtx)

	epochRewardsSysvarAcct, err := (*accts).GetAccount(&SysvarEpochRewardsAddr)
	if err != nil {
		return SysvarEpochRewards{}, InstrErrUnsupportedSysvar
	}

	if epochRewardsSysvarAcct.Lamports == 0 {
		return SysvarEpochRewards{}, InstrErrUnsupportedSysvar
	}

	dec := bin.NewBinDecoder(epochRewardsSysvarAcct.Data)

	var epochRewards SysvarEpochRewards
	epochRewards.MustUnmarshalWithDecoder(dec)

	return epochRewards, nil
}

func WriteEpochRewardsSysvar(accts *accounts.Accounts, epochRewards SysvarEpochRewards) {

	epochRewardsSysvarAcct, err := (*accts).GetAccount(&SysvarEpochRewardsAddr)
	if err != nil {
		panic("failed to read EpochRewards sysvar account")
	}

	data := new(bytes.Buffer)
	enc := bin.NewBinEncoder(data)

	err = epochRewards.MarshalWithEncoder(enc)

	epochRewardsSysvarAcct.Data = data.Bytes()

	err = (*accts).SetAccount(&SysvarEpochRewardsAddr, epochRewardsSysvarAcct)
	if err != nil {
		err = fmt.Errorf("failed write newly serialized EpochRewards sysvar to sysvar account: %w", err)
		panic(err)
	}
}
