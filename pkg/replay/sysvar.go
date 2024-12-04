package replay

import (
	"fmt"

	"github.com/Overclock-Validator/mithril/pkg/accounts"
	"github.com/Overclock-Validator/mithril/pkg/accountsdb"
	"github.com/Overclock-Validator/mithril/pkg/safemath"
	"github.com/Overclock-Validator/mithril/pkg/sealevel"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/tidwall/btree"
	"k8s.io/klog/v2"
)

const nsInSeconds = 1000000000

const maxAllowableDriftFast = 25
const maxAllowableDriftSlow = 150

type lastTimestampData struct {
	Timestamp int64
	Stake     uint64
}

func calculateStakeWeightedTimestamp(clock *sealevel.SysvarClock, epochSchedule *sealevel.SysvarEpochSchedule, block *Block) (int64, error) {
	slotsPerEpoch := epochSchedule.SlotsPerEpoch
	slotDuration := block.Manifest.Bank.NsPerSlot.BigInt().Uint64()

	var tsInfo btree.Map[int64, lastTimestampData]

	var totalStake uint64

	for _, v := range block.Manifest.Bank.Stakes.VoteAccounts {
		slotDelta, err := safemath.CheckedSubU64(block.Slot, v.Value.LastTimestampSlot)
		if err != nil {
			panic(fmt.Sprintf("checked sub failed in getTimestampEstimate. block.Slot: %d, LastTimestampSlot: %d", block.Slot, v.Value.LastTimestampSlot))
		}

		if slotDelta > slotsPerEpoch {
			continue
		}

		voteTimestamp := v.Value.LastTimestampTs
		offset := safemath.SaturatingMulU64(slotDuration, slotDelta)
		estimate := voteTimestamp + (int64(offset) / nsInSeconds)

		totalStake += v.Stake

		entry, ok := tsInfo.Get(estimate)
		if ok {
			entry.Stake += v.Stake
			tsInfo.Set(estimate, entry)
		} else {
			entry.Timestamp = estimate
			entry.Stake = v.Stake
			tsInfo.Set(estimate, entry)
		}
	}

	if totalStake == 0 {
		return 0, fmt.Errorf("zero stake")
	}

	var resultTimestamp int64

	var stakeAccumulator uint64

	iter := tsInfo.Iter()
	hasEntries := iter.First()
	if !hasEntries {
		return 0, fmt.Errorf("no entries")
	}

	for ; hasEntries; hasEntries = iter.Next() {
		entry := iter.Value()
		stakeAccumulator = safemath.SaturatingAddU64(stakeAccumulator, entry.Stake)

		if stakeAccumulator > (totalStake / 2) {
			resultTimestamp = entry.Timestamp
			break
		}
	}

	klog.Infof("stake weighted timestamp: %d, total stake %d", resultTimestamp, totalStake)

	epochStartSlot := epochSchedule.Slot0(clock.Epoch)
	pohEstimateOffset := safemath.SaturatingMulU64(slotDuration, safemath.SaturatingSubU64(block.Slot, epochStartSlot))
	estimateOffset := safemath.SaturatingMulU64(nsInSeconds, safemath.SaturatingSubU64(uint64(resultTimestamp), uint64(clock.EpochStartTimestamp)))
	maxDeltaFast := safemath.SaturatingMulU64(pohEstimateOffset, maxAllowableDriftFast) / 100
	maxDeltaSlow := safemath.SaturatingMulU64(pohEstimateOffset, maxAllowableDriftSlow) / 100

	klog.Infof("poh offset %d, estimate %d, fast %d, slow %d", pohEstimateOffset, estimateOffset, maxDeltaFast, maxDeltaSlow)

	if estimateOffset > pohEstimateOffset && safemath.SaturatingSubU64(estimateOffset, pohEstimateOffset) > maxDeltaSlow {
		resultTimestamp = clock.EpochStartTimestamp + int64(pohEstimateOffset/nsInSeconds) + int64(maxDeltaSlow/nsInSeconds)
	} else if estimateOffset < pohEstimateOffset && safemath.SaturatingSubU64(pohEstimateOffset, estimateOffset) > maxDeltaFast {
		resultTimestamp = clock.EpochStartTimestamp + int64(pohEstimateOffset/nsInSeconds) - int64(maxDeltaFast/nsInSeconds)
	}

	klog.Infof("corrected stake weighted timestamp: %d", resultTimestamp)

	if resultTimestamp < clock.UnixTimestamp {
		klog.Infof("updated timestamp to ancestor")
		resultTimestamp = clock.UnixTimestamp
	}

	return resultTimestamp, nil
}

func updateClockSysvar(clock *sealevel.SysvarClock, accountsDb *accountsdb.AccountsDb, block *Block) error {
	epochScheduleAcct, err := accountsDb.GetAccount(sealevel.SysvarEpochScheduleAddr)
	if err != nil {
		panic("unable to retrieve epoch schedule sysvar acct when updating clock sysvar")
	}

	decoder := bin.NewBinDecoder(epochScheduleAcct.Data)
	var epochSchedule sealevel.SysvarEpochSchedule
	err = epochSchedule.UnmarshalWithDecoder(decoder)
	if err != nil {
		panic(fmt.Sprintf("unable to unmarshal epoch schedule sysvar when updating clock sysvar"))
	}

	ancestorTimestamp := clock.UnixTimestamp

	clock.UnixTimestamp, err = calculateStakeWeightedTimestamp(clock, &epochSchedule, block)
	if err != nil {
		return err
	}

	clock.Slot = block.Slot

	epochOld := clock.Epoch
	epochNew := epochSchedule.GetEpoch(clock.Slot)
	clock.Epoch = epochNew

	if epochOld != epochNew {
		timestampEstimate, err := calculateStakeWeightedTimestamp(clock, &epochSchedule, block)
		if err != nil {
			return err
		}

		clock.UnixTimestamp = max(timestampEstimate, ancestorTimestamp)
		clock.EpochStartTimestamp = clock.UnixTimestamp
		clock.LeaderScheduleEpoch = epochSchedule.LeaderScheduleEpoch(clock.Slot)
	}

	return nil
}

func collectAndUpdateSysvarAcctsForAdh(slotCtx *sealevel.SlotCtx) []*accounts.Account {
	sysvarPubkeys := []solana.PublicKey{sealevel.SysvarClockAddr, sealevel.SysvarRecentBlockHashesAddr, sealevel.SysvarSlotHashesAddr, sealevel.SysvarSlotHistoryAddr}
	var sysvarAccts []*accounts.Account

	for _, pk := range sysvarPubkeys {
		acct, err := slotCtx.GetAccount(pk)
		if err != nil {
			panic(fmt.Sprintf("unable to get sysvar account for ADH: %s", pk))
		}

		if acct.Key == sealevel.SysvarRecentBlockHashesAddr {
			decoder := bin.NewBinDecoder(acct.Data)
			var recentBlockhashes sealevel.SysvarRecentBlockhashes

			err = recentBlockhashes.UnmarshalWithDecoder(decoder)
			if err != nil {
				panic(fmt.Sprintf("unable to unmarshal recent blockhashes sysvar"))
			}

			recentBlockhashes.PushLatest(slotCtx.Blockhash)
			newRecentBlockhashesBytes := recentBlockhashes.MustMarshal()
			copy(acct.Data, newRecentBlockhashesBytes)
		} else if acct.Key == sealevel.SysvarSlotHistoryAddr {
			decoder := bin.NewBinDecoder(acct.Data)
			var slotHistory sealevel.SysvarSlotHistory

			err = slotHistory.UnmarshalWithDecoder(decoder)
			if err != nil {
				panic(fmt.Sprintf("unable to unmarshal SlotHistory sysvar"))
			}

			slotHistory.Add(slotCtx.Slot)
			slotHistory.SetNextSlot(slotCtx.Slot + 1)
			newSlotHistoryBytes := slotHistory.MustMarshal()
			copy(acct.Data, newSlotHistoryBytes)
		}
		sysvarAccts = append(sysvarAccts, acct)
	}
	return sysvarAccts
}
