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

const SysvarEpochRewardsStructLen = 24

type SysvarEpochRewards struct {
	TotalRewards                    uint64
	DistributedRewards              uint64
	DistributionCompleteBlockHeight uint64
}

func (ser *SysvarEpochRewards) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {
	totalRewards, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read TotalRewards when decoding SysvarEpochRewards: %w", err)
	}
	ser.TotalRewards = totalRewards

	distributedRewards, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read DistributedRewards when decoding SysvarEpochRewards: %w", err)
	}
	ser.DistributedRewards = distributedRewards

	distributionCompleteBlockHeight, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read DistributionCompleteBlockHeight when decoding SysvarEpochRewards: %w", err)
	}
	ser.DistributionCompleteBlockHeight = distributionCompleteBlockHeight
	return
}

func (sr *SysvarEpochRewards) MustUnmarshalWithDecoder(decoder *bin.Decoder) {
	err := sr.UnmarshalWithDecoder(decoder)
	if err != nil {
		panic(err.Error())
	}
}

func ReadEpochRewardsSysvar(accts *accounts.Accounts) SysvarEpochRewards {
	epochRewardsSysvarAcct, err := (*accts).GetAccount(&SysvarEpochRewardsAddr)
	if err != nil {
		panic("failed to read epoch schedule sysvar account")
	}

	dec := bin.NewBinDecoder(epochRewardsSysvarAcct.Data)

	var epochRewards SysvarEpochRewards
	epochRewards.MustUnmarshalWithDecoder(dec)

	return epochRewards
}

func WriteEpochRewardsSysvar(accts *accounts.Accounts, epochRewards SysvarEpochRewards) {

	epochRewardsSysvarAcct, err := (*accts).GetAccount(&SysvarEpochRewardsAddr)
	if err != nil {
		panic("failed to read EpochRewards sysvar account")
	}

	data := new(bytes.Buffer)
	enc := bin.NewBinEncoder(data)

	err = enc.WriteUint64(epochRewards.TotalRewards, bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize TotalRewards for EpochRewards sysvar: %w", err)
		panic(err)
	}

	err = enc.WriteUint64(epochRewards.DistributedRewards, bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize DistributedRewards for EpochRewards sysvar: %w", err)
		panic(err)
	}

	err = enc.WriteUint64(epochRewards.DistributionCompleteBlockHeight, bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize DistributionCompleteBlockHeight for EpochRewards sysvar: %w", err)
		panic(err)
	}

	copy(epochRewardsSysvarAcct.Data, data.Bytes())

	err = (*accts).SetAccount(&SysvarEpochRewardsAddr, epochRewardsSysvarAcct)
	if err != nil {
		err = fmt.Errorf("failed write newly serialized EpochRewards sysvar to sysvar account: %w", err)
		panic(err)
	}
}
