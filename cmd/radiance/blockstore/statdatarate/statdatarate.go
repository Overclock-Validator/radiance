//go:build !lite

package statdatarate

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
	Use:   "stat-data-rate <rocksdb> <slots>",
	Short: "Produce CSV report of data rate at slot-level granularity",
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
	wr.Write([]string{"slot", "ts", "block_raw_bytes"})

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

	var blockRawBytes uint64
	for _, batch := range entries {
		blockRawBytes += uint64(len(batch.Raw))
	}

	wr.Write([]string{
		slotDecimal,
		strconv.FormatUint(meta.FirstShredTimestamp, 10),
		strconv.FormatUint(uint64(blockRawBytes), 10),
	})

	return nil
}
