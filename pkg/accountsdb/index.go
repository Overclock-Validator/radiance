package accountsdb

import (
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
)

type AccountIndexEntry struct {
	Slot   uint64
	FileId uint64
	Offset uint64
}

func (entry *AccountIndexEntry) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint64(entry.Slot, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(entry.FileId, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(entry.Offset, bin.LE)
	return err
}

func (entry *AccountIndexEntry) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error

	entry.Slot, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	entry.FileId, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	entry.Offset, err = decoder.ReadUint64(bin.LE)
	return err
}

func unmarshalAcctIdxEntry(data []byte) (*AccountIndexEntry, error) {
	decoder := bin.NewBinDecoder(data)
	acctIdxEntry := new(AccountIndexEntry)

	err := acctIdxEntry.UnmarshalWithDecoder(decoder)
	if err != nil {
		return nil, err
	}

	return acctIdxEntry, nil
}

func BuildIndexEntriesFromAppendVecs(data []byte, fileSize uint64, slot uint64, fileId uint64) ([]solana.PublicKey, []*AccountIndexEntry, error) {
	var offsetAndPubkeys []*AccountIndexEntry
	var pubkeys []solana.PublicKey

	var offset uint64

	parser := &avParser{Buf: data, FileSize: fileSize}

	for {
		pubkey, entry, err := parser.ParseAccount(offset, slot, fileId)
		if err != nil {
			break
		}

		pubkeys = append(pubkeys, pubkey)
		offsetAndPubkeys = append(offsetAndPubkeys, entry)
	}

	return pubkeys, offsetAndPubkeys, nil
}
