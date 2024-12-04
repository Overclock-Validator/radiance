//go:build !lite

package verifydata

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/Overclock-Validator/mithril/pkg/blockstore"
	"github.com/linxGnu/grocksdb"
	"github.com/vbauerster/mpb/v8"
	"k8s.io/klog/v2"
)

// worker does a single pass over blockstore.CfMeta and blockstore.CfDataShred concurrently.
type worker struct {
	id    uint
	meta  *grocksdb.Iterator
	shred *grocksdb.Iterator
	// Slot range
	current uint64
	stop    uint64
	ts      time.Time

	bar         *mpb.Bar
	numSuccess  *atomic.Uint64
	numSkipped  *atomic.Uint64
	numFailures *atomic.Uint32
	maxFailures uint32
	numTxns     *atomic.Uint64
	numBytes    *atomic.Uint64
}

func (w *worker) init(db *blockstore.DB, start uint64) {
	w.current = start
	w.meta = db.DB.NewIteratorCF(grocksdb.NewDefaultReadOptions(), db.CfMeta)
	w.shred = db.DB.NewIteratorCF(grocksdb.NewDefaultReadOptions(), db.CfDataShred)
	slotKey := blockstore.MakeSlotKey(start)
	w.meta.Seek(slotKey[:])
	w.shred.Seek(slotKey[:])
}

func (w *worker) close() {
	w.meta.Close()
	w.shred.Close()
}

func (w *worker) run(ctx context.Context) error {
	for w.readSlot() {
		// Non-blocking recv on context, bail if cancelled.
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
	if w.shouldAbort(w.numFailures.Load()) {
		return fmt.Errorf("too many failures")
	}
	return nil
}

func (w *worker) readSlot() (shouldContinue bool) {
	if !w.meta.Valid() || !w.shred.Valid() {
		return false
	}

	// Increment meta iter before returning.
	shouldContinue = true
	defer w.meta.Next()

	// Remember failure and increment failure counter before returning.
	var metaSlot uint64
	success := false
	var isFull bool
	defer func() {
		if !isFull {
			return
		}
		if success {
			w.numSuccess.Add(1)
		} else {
			if w.shouldAbort(w.numFailures.Add(1)) {
				shouldContinue = false
			}
		}
	}()

	// Meta iter indicates progress
	var ok bool
	metaSlot, ok = blockstore.ParseSlotKey(w.meta.Key().Data())
	if !ok {
		klog.Warningf("Skipping invalid slot key: %x", w.meta.Key().Data())
		return
	}
	if metaSlot >= w.stop {
		return false
	}
	defer func() {
		if success {
			if isFull {
				klog.V(3).Infof("[worker %d]: slot %d: ok", w.id, metaSlot)
			} else {
				klog.V(3).Infof("[worker %d]: slot %d: skipped", w.id, metaSlot)
			}
		}
	}()

	// Update progress bar
	step := metaSlot - w.current
	if step == 0 {
		step = 1
	}
	if metaSlot < w.current {
		step = 0 // ???
	}
	w.bar.IncrInt64(int64(step))
	w.current = metaSlot
	if step > 1 {
		w.numSkipped.Add(step - 1)
	}

	// Shred iterator should follow meta iter
	shredSlot, _, ok := blockstore.ParseShredKey(w.shred.Key().Data())
	if !ok {
		klog.Warningf("invalid shred key, syncing: %x", w.shred.Key().Data())
	} else if shredSlot < metaSlot {
		// Probably a skipped slots
		klog.V(4).Infof("slot %d: not all shreds consumed", metaSlot)
	} else if shredSlot > metaSlot {
		klog.Warningf("slot %d: missing shreds", metaSlot)
		return
	}

	// Synchronize shred iter with meta iter
	if !ok || shredSlot < metaSlot {
		w.shred.Seek(w.meta.Key().Data())
		if !w.shred.Valid() {
			klog.Warningf("slot %d: reached end of shreds", metaSlot)
		}
		shredSlot, _, ok = blockstore.ParseShredKey(w.shred.Key().Data())
		if !ok {
			// Double failure, just go to next slot
			klog.Warningf("slot %d: invalid shred key after sync: %x", metaSlot, w.shred.Key().Data())
			return
		}
	}

	numBytes := uint64(len(w.meta.Value().Data()))
	defer func() {
		w.numBytes.Add(numBytes)
	}()

	// Parse meta value.
	meta, err := blockstore.ParseBincode[blockstore.SlotMeta](w.meta.Value().Data())
	if err != nil {
		klog.Warningf("slot %d: invalid meta: %s", metaSlot, err)
		return
	}
	if isFull = meta.IsFull(); !isFull {
		w.numSkipped.Add(1)
		success = true
		return
	}

	// Read data shreds.
	shreds, err := blockstore.GetDataShredsFromIter(w.shred, metaSlot, 0, uint32(meta.Received), 2)
	if err != nil {
		klog.Warningf("slot %d: invalid data shreds: %s", metaSlot, err)
		return
	}

	// TODO Sigverify data shreds

	// Deshred and parse entries.
	entries, err := blockstore.DataShredsToEntries(meta, shreds)
	if err != nil {
		klog.Warningf("slot %d: cannot decode entries: %s", metaSlot, err)
		return
	}

	var numTxns uint64
	for _, outer := range entries {
		for _, e := range outer.Entries {
			numTxns += uint64(len(e.Txns))
			if *flagDumpSigs {
				for _, tx := range e.Txns {
					if len(tx.Signatures) > 0 {
						fmt.Println(tx.Signatures[0].String())
					}
				}
			}
		}
	}
	w.numTxns.Add(numTxns)

	// TODO Sigverify / sanitize txs

	success = true

	return
}

func (w *worker) shouldAbort(numFailures uint32) bool {
	return w.maxFailures > 0 && numFailures >= w.maxFailures
}
