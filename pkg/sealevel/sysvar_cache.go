package sealevel

import (
	"crypto/rand"

	"go.firedancer.io/radiance/pkg/base58"
)

const SysvarOwnerStr = "Sysvar1111111111111111111111111111111111111"

var SysvarOwnerAddr = base58.MustDecodeFromString(SysvarOwnerStr)

type SysvarCache struct {
	RecentBlockHashes *SysvarRecentBlockhashes
	Rent              SysvarRent
	Clock             SysvarClock
	Fees              SysvarFees
	SlotHashes        SysvarSlotHashes
}

func (sysvarCache *SysvarCache) GetRecentBlockHashes() *SysvarRecentBlockhashes {
	return sysvarCache.RecentBlockHashes
}

func (sysvarCache *SysvarCache) UpdateForSlot(slotCtx *SlotCtx) {
	if sysvarCache.RecentBlockHashes == nil {
		sysvarCache.RecentBlockHashes = new(SysvarRecentBlockhashes)
	}

	sysvarCache.Rent.InitializeDefault()
	sysvarCache.Clock.Update()
	sysvarCache.Fees.Update(slotCtx.LamportsPerSignature)
	sysvarCache.SlotHashes.UpdateWithSlotCtx(slotCtx)

}

func (sysvarCache *SysvarCache) AddRecentBlockHashEntry(entry RecentBlockHashesEntry) {
	if sysvarCache.RecentBlockHashes == nil {
		sysvarCache.RecentBlockHashes = new(SysvarRecentBlockhashes)
	}

	*sysvarCache.RecentBlockHashes = append(*sysvarCache.RecentBlockHashes, entry)
}

func (sysvarCache *SysvarCache) PopulateRecentBlockHashesForTesting() {
	var blockhash1 [32]byte
	var blockhash2 [32]byte
	var blockhash3 [32]byte
	var blockhash4 [32]byte

	rand.Read(blockhash1[:])
	rand.Read(blockhash2[:])
	rand.Read(blockhash3[:])
	rand.Read(blockhash4[:])

	feeCalculator := FeeCalculator{LamportsPerSignature: 1}
	entry1 := RecentBlockHashesEntry{Blockhash: blockhash1, FeeCalculator: feeCalculator}
	entry2 := RecentBlockHashesEntry{Blockhash: blockhash2, FeeCalculator: feeCalculator}
	entry3 := RecentBlockHashesEntry{Blockhash: blockhash3, FeeCalculator: feeCalculator}
	entry4 := RecentBlockHashesEntry{Blockhash: blockhash4, FeeCalculator: feeCalculator}

	sysvarCache.AddRecentBlockHashEntry(entry1)
	sysvarCache.AddRecentBlockHashEntry(entry2)
	sysvarCache.AddRecentBlockHashEntry(entry3)
	sysvarCache.AddRecentBlockHashEntry(entry4)
}
