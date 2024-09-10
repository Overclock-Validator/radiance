package accountsdb

import (
	"encoding/binary"
	"fmt"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/util"
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

func parseAcctAndAdvanceOffset(data []byte) (uint64, solana.PublicKey, bool, error) {
	var offset uint64
	offset += 8

	dataLen := binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	pubkey := solana.PublicKeyFromBytes(data[offset : offset+solana.PublicKeyLength])
	offset += 8

	lamports := binary.LittleEndian.Uint64(data[offset : offset+8])

	offset += 112

	if dataLen == 0 {
		return offset, pubkey, lamports == 0, nil
	}

	if (uint64(len(data)) - offset) < dataLen {
		return 0, solana.PublicKey{}, lamports == 0, fmt.Errorf("not enough data for %x byte, acct data len %d", dataLen, uint64(len(data))-offset)
	}

	offset += dataLen
	offset = util.AlignUp(offset, 8)

	return offset, pubkey, lamports == 0, nil
}

type offsetAndPubkey struct {
	Pubkey solana.PublicKey
	Offset uint64
}

func BuildIndexEntriesFromAppendVecs(data []byte, fileSize uint64, slot uint64, fileId uint64) ([]solana.PublicKey, []*AccountIndexEntry, error) {
	var offsetAndPubkeys []*AccountIndexEntry
	var pubkeys []solana.PublicKey

	var offset uint64

	for {
		if offset+hdrLen >= fileSize {
			break
		}

		if uint64(len(data[offset:])) < hdrLen {
			break
		}

		bytesReadAligned, pubkey, shouldSkip, err := parseAcctAndAdvanceOffset(data[offset:])
		if err != nil {
			return nil, nil, err
		}

		if !shouldSkip {
			offsetAndPubkeys = append(offsetAndPubkeys, &AccountIndexEntry{Slot: slot, FileId: fileId, Offset: offset})
			pubkeys = append(pubkeys, pubkey)
		}

		offset += bytesReadAligned
	}

	return pubkeys, offsetAndPubkeys, nil
}
