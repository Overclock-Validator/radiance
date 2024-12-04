//go:build !lite

package dumpbatches

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Overclock-Validator/mithril/cmd/radiance/blockstore/util"
	"github.com/Overclock-Validator/mithril/pkg/blockstore"
	"github.com/Overclock-Validator/mithril/pkg/shred"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

var Cmd = cobra.Command{
	Use:   "dump-batches <rocksdb> <out> <slots>",
	Short: "Dump shred/microblock batches to file system",
	Long: `dump-batches writes raw serialized shred data batches from RocksDB to the file system.

Creates file paths ./<out>/<slot>/batch<index>.bin`,
	Example: `    dump-shreds ./rocksdb ./batches 1:3,4
./batches/1/batch0.bin
...
./batches/2/batch0.bin
./batches/2/batch1.bin
...
./batches/3/batch0.bin
...
./batches/4/batch0.bin
./batches/4/batch1.bin
./batches/4/batch2.bin`,
	Args: cobra.ExactArgs(3),
}

func init() {
	Cmd.Run = run
}

func run(_ *cobra.Command, args []string) {
	rocksDB := args[0]
	outPath := args[1]

	db, err := blockstore.OpenReadOnly(rocksDB)
	if err != nil {
		klog.Exitf("Failed to open blockstore: %s", err)
	}
	defer db.Close()

	if err := os.Mkdir(outPath, 0755); err != nil && !errors.Is(err, fs.ErrExist) {
		klog.Exit(err)
	}

	slots, ok := util.ParseInts(args[2])
	if !ok {
		klog.Exit("Invalid slots parameter")
	}
	slots.Iter(func(slot uint64) bool {
		err := dumpSlot(db, outPath, slot)
		if err != nil {
			klog.Warning("Failed to dump slot %d: %s", slot, err)
		}
		return true
	})
}

func dumpSlot(db *blockstore.DB, outPath string, slot uint64) error {
	slotPath := filepath.Join(outPath, strconv.FormatUint(slot, 10))
	if err := os.Mkdir(slotPath, 0755); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}

	meta, err := db.GetSlotMeta(slot)
	if err != nil {
		return fmt.Errorf("while getting slot meta %d: %w", slot, err)
	}

	batches, err := db.GetEntries(meta, shred.RevisionV2)
	if err != nil {
		return fmt.Errorf("while getting batches in slot %d: %w", slot, err)
	}

	for i, batch := range batches {
		p := filepath.Join(slotPath, fmt.Sprintf("batch%d.bin", i))
		if err := os.WriteFile(p, batch.Raw, 0644); err != nil {
			return err
		}
		fmt.Println(p)
	}

	return nil
}
