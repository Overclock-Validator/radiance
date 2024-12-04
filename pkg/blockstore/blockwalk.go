package blockstore

import "github.com/Overclock-Validator/mithril/pkg/shred"

// BlockWalkI abstracts iterators over block data.
//
// The main (and only) implementation in this package is BlockWalk.
type BlockWalkI interface {
	Seek(slot uint64) (ok bool)
	SlotsAvailable() (total uint64)
	Next() (meta *SlotMeta, ok bool)
	Close()

	// Entries returns the block contents of a slot.
	//
	// The outer returned slice contains batches of entries.
	// Each batch is made up from multiple shreds and shreds and batches are aligned.
	// The SlotMeta.EntryEndIndexes mark the indexes of the last shreds in each batch,
	// thus `len(SlotMeta.EntryEndIndexes)` equals `len(batches)`.
	//
	// The inner slices are the entries in each shred batch, usually sized one.
	Entries(meta *SlotMeta) (batches [][]shred.Entry, err error)
}
