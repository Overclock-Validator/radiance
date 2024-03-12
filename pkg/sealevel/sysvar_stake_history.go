package sealevel

import (
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
	"go.firedancer.io/radiance/pkg/global"
)

const SysvarStakeHistoryAddrStr = "SysvarStakeHistory1111111111111111111111111"

var SysvarStakeHistoryAddr = base58.MustDecodeFromString(SysvarSlotHashesAddrStr)

type StakeHistoryEntry struct {
	Effective    uint64
	Activating   uint64
	Deactivating uint64
}

type StakeHistoryPair struct {
	Epoch uint64
	Entry StakeHistoryEntry
}

type SysvarStakeHistory []StakeHistoryPair

func (sh *SysvarStakeHistory) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {
	entriesLen, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read length of entries when decoding SysvarStakeHistory: %w", err)
	}

	stakeHistory := *sh

	for count := 0; count < int(entriesLen); count++ {

		stakeHistoryPair := StakeHistoryPair{}
		stakeHistoryPair.Epoch, err = decoder.ReadUint64(bin.LE)
		if err != nil {
			return fmt.Errorf("failed to read Epoch when decoding SysvarStakeHistory: %w", err)
		}

		stakeHistoryPair.Entry.Effective, err = decoder.ReadUint64(bin.LE)
		if err != nil {
			return fmt.Errorf("failed to read Effective when decoding SysvarStakeHistory: %w", err)
		}

		stakeHistoryPair.Entry.Activating, err = decoder.ReadUint64(bin.LE)
		if err != nil {
			return fmt.Errorf("failed to read Activating when decoding SysvarStakeHistory: %w", err)
		}

		stakeHistoryPair.Entry.Deactivating, err = decoder.ReadUint64(bin.LE)
		if err != nil {
			return fmt.Errorf("failed to read Deactivating when decoding SysvarStakeHistory: %w", err)
		}

		stakeHistory = append(stakeHistory, stakeHistoryPair)
	}

	return
}

func (sh *SysvarStakeHistory) MustUnmarshalWithDecoder(decoder *bin.Decoder) {
	err := sh.UnmarshalWithDecoder(decoder)
	if err != nil {
		panic(err.Error())
	}
}

func ReadStakeHistorySysvar(accts *accounts.Accounts) SysvarStakeHistory {
	stakeHistorySysvarAcct, err := (*accts).GetAccount(&SysvarStakeHistoryAddr)
	if err != nil {
		panic("failed to read StakeHistory sysvar account")
	}

	dec := bin.NewBinDecoder(stakeHistorySysvarAcct.Data)

	var stakeHistory SysvarStakeHistory
	stakeHistory.MustUnmarshalWithDecoder(dec)

	return stakeHistory
}

// TODO: implement logic for writing the StakeHistory sysvar and for creating a default
func UpdateStakeHistorySysvar(globalCtx *global.GlobalCtx, newStakeHistory *SysvarStakeHistory) {

}
