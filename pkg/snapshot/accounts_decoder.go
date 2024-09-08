package snapshot

import (
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/util"
)

const hdrLen = 136

func unpackOffsetAndPubkey(data []byte) (uint64, solana.PublicKey, bool, error) {
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

func buildIndexEntriesFromAppendVecs(data []byte, fileSize uint64, slot uint64, fileId uint64) ([]solana.PublicKey, []*accounts.AccountIndexEntry, error) {
	var offsetAndPubkeys []*accounts.AccountIndexEntry
	var pubkeys []solana.PublicKey

	var offset uint64

	for {
		if offset+hdrLen >= fileSize {
			break
		}

		if uint64(len(data[offset:])) < hdrLen {
			break
		}

		bytesReadAligned, pubkey, shouldSkip, err := unpackOffsetAndPubkey(data[offset:])
		if err != nil {
			return nil, nil, err
		}

		offset += bytesReadAligned

		if shouldSkip {
			continue
		}

		offsetAndPubkeys = append(offsetAndPubkeys, &accounts.AccountIndexEntry{Slot: slot, FileId: fileId, Offset: offset})
		pubkeys = append(pubkeys, pubkey)
	}

	return pubkeys, offsetAndPubkeys, nil
}
