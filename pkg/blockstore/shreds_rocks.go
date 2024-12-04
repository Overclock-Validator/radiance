//go:build !lite

package blockstore

import (
	"encoding/binary"
	"fmt"

	"github.com/Overclock-Validator/mithril/pkg/shred"
	"github.com/linxGnu/grocksdb"
)

func (d *DB) GetEntries(meta *SlotMeta, shredRevision int) ([]Entries, error) {
	shreds, err := d.GetDataShreds(meta.Slot, 0, uint32(meta.Received), shredRevision)
	if err != nil {
		return nil, err
	}
	return DataShredsToEntries(meta, shreds)
}

func (d *DB) GetAllDataShreds(slot uint64, revision int) ([]shred.Shred, error) {
	return d.getAllShreds(d.CfDataShred, slot, revision)
}

func (d *DB) GetDataShreds(slot uint64, startIdx, endIdx uint32, revision int) ([]shred.Shred, error) {
	iter := d.DB.NewIteratorCF(grocksdb.NewDefaultReadOptions(), d.CfDataShred)
	defer iter.Close()
	key := MakeShredKey(slot, uint64(startIdx))
	iter.Seek(key[:])
	return GetDataShredsFromIter(iter, slot, startIdx, endIdx, revision)
}

// GetDataShredsFromIter is like GetDataShreds, but takes a custom iterator.
// The iterator must be seeked to the indicated slot/startIdx.
func GetDataShredsFromIter(
	iter *grocksdb.Iterator,
	slot uint64,
	startIdx, endIdx uint32,
	revision int,
) ([]shred.Shred, error) {
	var shreds []shred.Shred
	for i := startIdx; i < endIdx; i++ {
		var curSlot, index uint64
		valid := iter.Valid()
		if valid {
			key := iter.Key().Data()
			if len(key) != 16 {
				continue
			}
			curSlot = binary.BigEndian.Uint64(key)
			index = binary.BigEndian.Uint64(key[8:])
		}
		if !valid || curSlot != slot {
			return nil, fmt.Errorf("missing shreds for slot %d", slot)
		}
		if index != uint64(i) {
			return nil, fmt.Errorf("missing shred %d for slot %d", i, index)
		}
		s := shred.NewShredFromSerialized(iter.Value().Data(), revision)
		if !s.Ok() {
			return nil, fmt.Errorf("failed to deserialize shred %d/%d", slot, i)
		}
		shreds = append(shreds, s)
		iter.Next()
	}
	return shreds, nil
}

func (d *DB) GetDataShred(slot, index uint64, revision int) shred.Shred {
	return d.getShred(d.CfDataShred, slot, index, revision)
}

func (d *DB) GetRawDataShred(slot, index uint64) (*grocksdb.Slice, error) {
	return d.getRawShred(d.CfDataShred, slot, index)
}

func (d *DB) GetAllCodeShreds(slot uint64) ([]shred.Shred, error) {
	return d.getAllShreds(d.CfDataShred, slot, shred.RevisionV2)
}

func (d *DB) GetCodeShred(slot, index uint64) shred.Shred {
	return d.getShred(d.CfCodeShred, slot, index, shred.RevisionV2)
}

func (d *DB) GetRawCodeShred(slot, index uint64) (*grocksdb.Slice, error) {
	return d.getRawShred(d.CfCodeShred, slot, index)
}

func (d *DB) getRawShred(
	cf *grocksdb.ColumnFamilyHandle,
	slot, index uint64,
) (*grocksdb.Slice, error) {
	opts := grocksdb.NewDefaultReadOptions()
	key := MakeShredKey(slot, index)
	return d.DB.GetCF(opts, cf, key[:])
}

func (d *DB) getShred(
	cf *grocksdb.ColumnFamilyHandle,
	slot, index uint64,
	revision int,
) (s shred.Shred) {
	value, err := d.getRawShred(cf, slot, index)
	if err != nil {
		return
	}
	defer value.Free()
	return shred.NewShredFromSerialized(value.Data(), revision)
}

func (d *DB) getAllShreds(
	cf *grocksdb.ColumnFamilyHandle,
	slot uint64,
	revision int,
) ([]shred.Shred, error) {
	iter := d.DB.NewIteratorCF(grocksdb.NewDefaultReadOptions(), cf)
	defer iter.Close()
	prefix := MakeSlotKey(slot)
	iter.Seek(prefix[:])
	var shreds []shred.Shred
	for iter.ValidForPrefix(prefix[:]) {
		s := shred.NewShredFromSerialized(iter.Value().Data(), revision)
		if !s.Ok() {
			return nil, fmt.Errorf("invalid shred %d/%d", slot, len(shreds))
		}
		shreds = append(shreds, s)
		iter.Next()
	}
	return shreds, nil
}
