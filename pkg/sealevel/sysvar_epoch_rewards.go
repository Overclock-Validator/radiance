package sealevel

import (
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
	"go.firedancer.io/radiance/pkg/global"
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

// TODO: implement logic for writing the epoch rewards sysvar and for creating a default
func UpdateEpochRewardsSysvar(globalCtx *global.GlobalCtx, newEpochSchedule *SysvarEpochRewards) {

}
