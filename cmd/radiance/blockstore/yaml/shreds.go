package yaml

import (
	"encoding/base64"
	"encoding/json"

	"github.com/Overclock-Validator/mithril/pkg/blockstore"
	"github.com/Overclock-Validator/mithril/pkg/shred"
)

// entryBatch is a YAML-friendly version of blockstore.Entries.
type entryBatch struct {
	Shreds      []uint32 `yaml:"shreds,flow"`
	EncodedSize int      `yaml:"encoded_size,omitempty"`
	NumEntries  int      `yaml:"num_entries"`
	Entries     []entry  `yaml:"entries"`
}

func makeEntryBatch(b *blockstore.Entries, withTxs bool) entryBatch {
	es := make([]entry, len(b.Entries))
	for i, e := range b.Entries {
		es[i] = makeEntry(&e, withTxs)
	}
	shreds := make([]uint32, len(b.Shreds))
	for i, s := range b.Shreds {
		shreds[i] = s.Index
	}
	return entryBatch{
		Entries:     es,
		NumEntries:  len(es),
		Shreds:      shreds,
		EncodedSize: len(b.Raw),
	}
}

// entry is a YAML-friendly version of shred.Entry.
type entry struct {
	NumHashes uint64 `yaml:"num_hashes"`
	Hash      string `yaml:"hash"`
	NumTxns   int    `yaml:"num_txns"`
	Txns      []any  `yaml:"txns,omitempty"`
}

func makeEntry(e *shred.Entry, withTxs bool) entry {
	var txJSONs []any
	if withTxs {
		// Hacky and slow serializer to make txn YAML output tolerable
		//
		// The main problem is that the YAML serializer formats byte slices as arrays,
		// whereas JSON serializer outputs base64 strings, which is what we want.
		//
		// This indirection effectively creates a dynamic data structure out of a strongly typed Txn,
		// replacing all byte slices in with strings.
		txJSONs = make([]any, len(e.Txns))
		for i, txn := range e.Txns {
			txJSON, _ := json.Marshal(txn)
			_ = json.Unmarshal(txJSON, &txJSONs[i])
		}
	}
	return entry{
		NumHashes: e.NumHashes,
		Hash:      base64.StdEncoding.EncodeToString(e.Hash[:]),
		NumTxns:   len(e.Txns),
		Txns:      txJSONs,
	}
}
