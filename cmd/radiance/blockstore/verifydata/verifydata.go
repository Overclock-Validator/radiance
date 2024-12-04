//go:build !lite

package verifydata

import (
	"context"
	"io"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/Overclock-Validator/mithril/pkg/blockstore"
	"github.com/VividCortex/ewma"
	"github.com/linxGnu/grocksdb"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

var Cmd = cobra.Command{
	Use:   "verify-data <rocksdb>",
	Short: "Verify ledger data integrity",
	Long: "Iterates through all data shreds and performs sanity checks.\n" +
		"Useful for checking the correctness of the Radiance implementation.\n" +
		"\n" +
		"Scans through the data-shreds column family with multiple threads (divide-and-conquer).",
	Args: cobra.ExactArgs(1),
}

var flags = Cmd.Flags()

var (
	flagWorkers  = flags.UintP("workers", "w", uint(runtime.NumCPU()), "Number of goroutines to verify with")
	flagMaxErrs  = flags.Uint32("max-errors", 100, "Abort after N errors")
	flagStatIvl  = flags.Duration("stat-interval", 5*time.Second, "Stats interval")
	flagDumpSigs = flags.Bool("dump-sigs", false, "Print first signature of each transaction")
)

// TODO add a progress bar :3

func init() {
	Cmd.Run = run
}

func run(c *cobra.Command, args []string) {
	start := time.Now()

	workers := *flagWorkers
	if workers == 0 {
		workers = uint(runtime.NumCPU())
	}

	rocksDB := args[0]
	db, err := blockstore.OpenReadOnly(rocksDB)
	if err != nil {
		klog.Exitf("Failed to open blockstore: %s", err)
	}
	defer db.Close()

	// total amount of slots
	slotLo, slotHi, ok := slotBounds(db)
	if !ok {
		klog.Exitf("Cannot find slot boundaries")
	}
	if slotLo > slotHi {
		panic("wtf: slotLo > slotHi")
	}
	total := slotHi - slotLo
	klog.Infof("Verifying %d slots", total)

	// per-worker amount of slots
	step := total / uint64(workers)
	if step == 0 {
		step = 1
	}
	cursor := slotLo
	klog.Infof("Slots per worker: %d", step)

	// stats trackers
	var numSuccess atomic.Uint64
	var numSkipped atomic.Uint64
	var numFailure atomic.Uint32
	var numBytes atomic.Uint64
	var numTxns atomic.Uint64

	// application lifetime
	rootCtx := c.Context()
	ctx, cancel := context.WithCancel(rootCtx)
	defer cancel()
	group, ctx := errgroup.WithContext(ctx)

	txRate := ewma.NewMovingAverage(7)
	lastStatsUpdate := time.Now()
	var lastNumTxns uint64
	updateEWMA := func() {
		now := time.Now()
		sinceLast := now.Sub(lastStatsUpdate)
		curNumTxns := numTxns.Load()
		increase := curNumTxns - lastNumTxns
		iRate := float64(increase) / sinceLast.Seconds()
		txRate.Add(iRate)
		lastNumTxns = curNumTxns
		lastStatsUpdate = now
	}
	stats := func() {
		klog.Infof("[stats] good=%d skipped=%d bad=%d tps=%.0f",
			numSuccess.Load(), numSkipped.Load(), numFailure.Load(), txRate.Value())
	}

	var barOutput io.Writer
	isAtty := isatty.IsTerminal(os.Stderr.Fd())
	if isAtty {
		barOutput = os.Stderr
	} else {
		barOutput = io.Discard
	}

	progress := mpb.NewWithContext(ctx, mpb.WithOutput(barOutput))
	bar := progress.New(int64(total), mpb.BarStyle(),
		mpb.PrependDecorators(
			decor.Spinner(nil),
			decor.CurrentNoUnit(" %d"),
			decor.TotalNoUnit(" / %d slots"),
			decor.NewPercentage(" (% d)"),
		),
		mpb.AppendDecorators(
			decor.Name("eta="),
			decor.AverageETA(decor.ET_STYLE_GO),
		))

	if isAtty {
		klog.LogToStderr(false)
		klog.SetOutput(progress)
	}

	statInterval := *flagStatIvl
	if statInterval > 0 {
		statTicker := time.NewTicker(statInterval)
		rateTicker := time.NewTicker(250 * time.Millisecond)
		go func() {
			defer statTicker.Stop()
			defer rateTicker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-statTicker.C:
					stats()
				case <-rateTicker.C:
					updateEWMA()
				}
			}
		}()
	}

	for i := uint(0); i < workers; i++ {
		// Find segment assigned to worker
		wLo := cursor
		wHi := wLo + step
		if wHi > slotHi || i == workers-1 {
			wHi = slotHi
		}
		cursor = wHi
		if wLo >= wHi {
			break
		}

		klog.Infof("[worker %d]: range=[%d:%d]", i, wLo, wHi)
		w := &worker{
			id:          i,
			bar:         bar,
			stop:        wHi,
			numSuccess:  &numSuccess,
			numSkipped:  &numSkipped,
			numFailures: &numFailure,
			maxFailures: *flagMaxErrs,
			numBytes:    &numBytes,
			numTxns:     &numTxns,
		}
		w.init(db, wLo)
		group.Go(func() error {
			defer w.close()
			return w.run(ctx)
		})
	}

	err = group.Wait()
	if isAtty {
		klog.Flush()
		klog.SetOutput(os.Stderr)
	}

	var exitCode int
	if err != nil {
		klog.Errorf("Aborting: %s", err)
		exitCode = 1
	} else if err = rootCtx.Err(); err == nil {
		klog.Info("Done!")
		exitCode = 0
	} else {
		klog.Infof("Aborted: %s", err)
		exitCode = 1
	}

	stats()
	timeTaken := time.Since(start)
	klog.Infof("Time taken: %s", timeTaken)
	klog.Infof("Bytes Read: %d (%.2f MB/s)", numBytes.Load(), float64(numBytes.Load())/timeTaken.Seconds()/1000000)
	klog.Infof("Transaction Count: %d (%.2f tps)", numTxns.Load(), float64(numTxns.Load())/timeTaken.Seconds())
	os.Exit(exitCode)
}

// slotBounds returns the lowest and highest available slots in the meta table.
func slotBounds(db *blockstore.DB) (low uint64, high uint64, ok bool) {
	iter := db.DB.NewIteratorCF(grocksdb.NewDefaultReadOptions(), db.CfMeta)
	defer iter.Close()

	iter.SeekToFirst()
	if ok = iter.Valid(); !ok {
		return
	}
	low, ok = blockstore.ParseSlotKey(iter.Key().Data())
	if !ok {
		return
	}

	iter.SeekToLast()
	if ok = iter.Valid(); !ok {
		return
	}
	high, ok = blockstore.ParseSlotKey(iter.Key().Data())
	high++
	return
}
