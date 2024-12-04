package blockstore

import (
	"testing"

	"github.com/Overclock-Validator/mithril/fixtures"
)

func BenchmarkDataShredsToEntries_mainnet102815960(b *testing.B) {
	rawShreds := fixtures.DataShreds(nil, "mainnet", 102815960)
	shreds := parseShreds(nil, rawShreds, 2)
	meta := &SlotMeta{
		Consumed:           1427,
		Received:           1427,
		LastIndex:          1426,
		NumEntryEndIndexes: 574,
		EntryEndIndexes:    mainnet_102815960_EntryEndIndexes,
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := DataShredsToEntries(meta, shreds)
		if err != nil {
			panic(err)
		}
	}
}
