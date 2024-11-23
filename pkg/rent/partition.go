package rent

import (
	"encoding/binary"
	"fmt"
	"math"
	"slices"

	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/sealevel"
)

const (
	prefixSize = 8
	prefixMax  = math.MaxUint64
)

// pub type Partition = (PartitionIndex, PartitionIndex, PartitionsPerCycle);
type Partition struct {
	StartIdx       uint64
	EndIdx         uint64
	PartitionCount uint64
}

type RentCollectionCycleParams struct {
	Epoch              uint64
	SlotCountPerEpoch  uint64
	MultiEpochCycle    bool
	BaseEpoch          uint64
	EpochCountPerCycle uint64
	PartitionCount     uint64
}

// startSlot = parent slot
// endSlot = current slot
func RentCollectionPartitions(startSlot uint64, endSlot uint64, epochSchedule *sealevel.SysvarEpochSchedule) []Partition {
	startEpoch, startSlotIdx := epochSchedule.GetEpochAndSlotIndex(startSlot)
	endEpoch, endSlotIdx := epochSchedule.GetEpochAndSlotIndex(endSlot)

	partitions := make([]Partition, 0)

	if startEpoch < endEpoch {
		// TODO: implement
		panic("cross epoch rent collection")
	} else {
		partition := partitionFromNormalSlotIndices(startSlotIdx, endSlotIdx, endEpoch, epochSchedule)
		partitions = append(partitions, partition)
	}

	return partitions
}

func partitionIdxFromSlotIdx(slotIdxInEpoch uint64, cycleParams RentCollectionCycleParams) uint64 {
	epochOffset := cycleParams.Epoch - cycleParams.BaseEpoch
	epochIdxInCycle := epochOffset % cycleParams.EpochCountPerCycle
	return slotIdxInEpoch + (epochIdxInCycle * cycleParams.SlotCountPerEpoch)
}

func partitionFromSlotIndices(cycleParams RentCollectionCycleParams, startSlotIdx uint64, endSlotIdx uint64) Partition {
	partitionCount := cycleParams.PartitionCount

	startPartitionIdx := partitionIdxFromSlotIdx(startSlotIdx, cycleParams)
	endPartitionIdx := partitionIdxFromSlotIdx(endSlotIdx, cycleParams)

	// TODO: implement logic for special edgecases

	return Partition{StartIdx: startPartitionIdx, EndIdx: endPartitionIdx, PartitionCount: partitionCount}
}

func partitionFromNormalSlotIndices(startSlotIdx uint64, endSlotIdx uint64, epoch uint64, epochSchedule *sealevel.SysvarEpochSchedule) Partition {
	slotsPerEpoch := epochSchedule.SlotsInEpoch(epoch)
	cycleParams := RentCollectionCycleParams{Epoch: epoch, SlotCountPerEpoch: slotsPerEpoch, MultiEpochCycle: false, BaseEpoch: 0, EpochCountPerCycle: 1, PartitionCount: slotsPerEpoch}
	return partitionFromSlotIndices(cycleParams, startSlotIdx, endSlotIdx)
}

type PubkeyRange struct {
	StartPubkey solana.PublicKey
	EndPubkey   solana.PublicKey
	StartPrefix uint64
	EndPrefix   uint64
}

func pubkeyRangeFromPartition(partition Partition) PubkeyRange {
	startPubkey := slices.Repeat([]byte{0x00}, 32)
	endPubkey := slices.Repeat([]byte{0xff}, 32)

	// TODO: implement partition_count == 0 case

	partitionWidth := (prefixMax-partition.PartitionCount+1)/partition.PartitionCount + 1

	var startKeyPrefix uint64
	if partition.StartIdx == 0 && partition.EndIdx == 0 {
		startKeyPrefix = 0
	} else if partition.StartIdx+1 == partition.PartitionCount {
		startKeyPrefix = prefixMax
	} else {
		startKeyPrefix = (partition.StartIdx + 1) * partitionWidth
	}

	var endKeyPrefix uint64
	if partition.EndIdx+1 == partition.PartitionCount {
		endKeyPrefix = prefixMax
	} else {
		endKeyPrefix = (partition.EndIdx+1)*partitionWidth - 1
	}

	if partition.StartIdx != 0 && partition.StartIdx == partition.EndIdx {
		if endKeyPrefix == prefixMax {
			startKeyPrefix = endKeyPrefix
			startPubkey = endPubkey
		} else {
			endKeyPrefix = startKeyPrefix
			endPubkey = startPubkey
		}
	}

	prefixBytesBuf := make([]byte, 8)

	binary.BigEndian.PutUint64(prefixBytesBuf, startKeyPrefix)
	copy(startPubkey[0:prefixSize], prefixBytesBuf)
	binary.BigEndian.PutUint64(prefixBytesBuf, endKeyPrefix)
	copy(endPubkey[0:prefixSize], prefixBytesBuf)

	startPubkeyFinal := solana.PublicKeyFromBytes(startPubkey)
	endPubkeyFinal := solana.PublicKeyFromBytes(endPubkey)

	fmt.Printf("rent partition - startPubkey: %s, endPubkey: %s. range %d\n", startPubkeyFinal, endPubkeyFinal, endKeyPrefix-startKeyPrefix)

	return PubkeyRange{StartPubkey: startPubkeyFinal, EndPubkey: endPubkeyFinal, StartPrefix: startKeyPrefix, EndPrefix: endKeyPrefix}
}
