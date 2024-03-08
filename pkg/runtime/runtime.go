// Package runtime provides low-level components of the Solana Execution Layer.
package runtime

import "time"

type PohParams struct {
	TickDuration     time.Duration
	HasTickCount     bool
	TickCount        uint64
	HasHashesPerTick bool
	HashesPerTick    uint64
}

type InflationParams struct {
	Initial        float64
	Terminal       float64
	Taper          float64
	Foundation     float64
	FoundationTerm float64
	Padding00      [8]byte
}

type EpochSchedule struct {
	SlotPerEpoch             uint64
	LeaderScheduleSlotOffset uint64
	Warmup                   bool
	FirstNormalEpoch         uint64
	FirstNormalSlot          uint64
}

type FeeParams struct {
	TargetLamportsPerSig uint64
	TargetSigsPerSlot    uint64
	MinLamportsPerSig    uint64
	MaxLamportsPerSig    uint64
	BurnPercent          uint8
}

type RentParams struct {
	LamportsPerByteYear uint64
	ExemptionThreshold  float64
	BurnPercent         uint8
}
