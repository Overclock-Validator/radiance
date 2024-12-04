//go:build !lite

package statentries

import (
	"encoding/csv"
	"os"
	"strconv"

	"github.com/Overclock-Validator/mithril/cmd/radiance/blockstore/util"
	"github.com/Overclock-Validator/mithril/pkg/blockstore"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

var Cmd = cobra.Command{
	Use:   "stat-entries <rocksdb> <slots>",
	Short: "Produce CSV report at entry-level granularity",
	Args:  cobra.ExactArgs(2),
}

func init() {
	Cmd.Run = run
}

func run(_ *cobra.Command, args []string) {
	slots, ok := util.ParseInts(args[1])
	if !ok {
		klog.Exit("Invalid slots parameter")
	}

	db, err := blockstore.OpenReadOnly(args[0])
	if err != nil {
		klog.Exitf("Failed to open blockstore: %s", err)
	}
	defer db.Close()

	wr := csv.NewWriter(os.Stdout)
	defer wr.Flush()
	wr.Write([]string{"slot", "batch_idx", "entry_idx", "hash_cnt", "txn_cnt", "accum_tick_cnt"})

	slots.Iter(func(slot uint64) bool {
		err := dumpSlot(db, wr, slot)
		if err != nil {
			klog.Warningf("Failed to dump slot %d: %s", slot, err)
		}
		return true
	})
}

func dumpSlot(db *blockstore.DB, wr *csv.Writer, slot uint64) error {
	slotDecimal := strconv.FormatUint(slot, 10)

	meta, err := db.GetSlotMeta(slot)
	if err != nil {
		return err
	}
	entries, err := db.GetEntries(meta, 2)
	if err != nil {
		return err
	}

	accumTickCnt := uint64(0)
	for batchIdx, batch := range entries {
		batchDecimal := strconv.FormatUint(uint64(batchIdx), 10)
		for entryIdx, entry := range batch.Entries {
			if entry.NumHashes > 1 {
				accumTickCnt++
			}
			wr.Write([]string{
				slotDecimal,
				batchDecimal,
				strconv.FormatUint(uint64(entryIdx), 10),
				strconv.FormatUint(entry.NumHashes, 10),
				strconv.FormatUint(uint64(len(entry.Txns)), 10),
				strconv.FormatUint(accumTickCnt, 10),
			})
		}
	}

	return nil
}
