package replay

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"

	"github.com/gagliardetto/solana-go"
	"github.com/zeebo/blake3"
	"go.firedancer.io/radiance/pkg/accounts"
)

type acctHash struct {
	Pubkey solana.PublicKey
	Hash   [32]byte
}

func newAcctHash(pubkey solana.PublicKey, hash []byte) acctHash {
	pair := acctHash{Pubkey: pubkey}
	copy(pair.Hash[:], hash)
	return pair
}

func calculateSingleAcctHash(acct accounts.Account) acctHash {
	hasher := blake3.New()

	var lamportBytes [8]byte
	binary.LittleEndian.PutUint64(lamportBytes[:], acct.Lamports)
	_, _ = hasher.Write(lamportBytes[:])

	var rentEpochBytes [8]byte
	binary.LittleEndian.PutUint64(rentEpochBytes[:], acct.RentEpoch)
	_, _ = hasher.Write(rentEpochBytes[:])

	_, _ = hasher.Write(acct.Data)

	if acct.Executable {
		_, _ = hasher.Write([]byte{1})
	} else {
		_, _ = hasher.Write([]byte{0})
	}

	_, _ = hasher.Write(acct.Owner[:])
	_, _ = hasher.Write(acct.Key[:])

	return newAcctHash(acct.Key, hasher.Sum(nil))
}

func calculateAccountHashes(accts []*accounts.Account) []acctHash {
	pairs := make([]acctHash, len(accts))
	for idx, acct := range accts {
		pair := calculateSingleAcctHash(*acct)
		pairs[idx] = pair
	}
	return pairs
}

const maxMerkleHeight = 16
const merkleFanout = 16

func divCeil(x uint64, y uint64) uint64 {
	result := x / y
	if (x % y) != 0 {
		result++
	}
	return result
}

func computeMerkleRootLoop(acctHashes [][]byte) []byte {
	if len(acctHashes) == 0 {
		return nil
	}

	totalHashes := uint64(len(acctHashes))
	chunks := divCeil(totalHashes, merkleFanout)

	results := make([][]byte, chunks)

	for i := uint64(0); i < chunks; i++ {
		startIdx := i * merkleFanout
		endIdx := min(startIdx+merkleFanout, totalHashes)

		hasher := sha256.New()
		a := acctHashes[startIdx:endIdx]

		for _, h := range a {
			hasher.Write(h)
		}

		results[i] = hasher.Sum(nil)
	}

	if len(results) == 1 {
		return results[0]
	} else {
		return computeMerkleRootLoop(results)
	}
}

func pubkeyCmp(a solana.PublicKey, b solana.PublicKey) bool {
	for i := uint64(0); i < 4; i++ {
		a1 := binary.BigEndian.Uint64(a[8*i:])
		b1 := binary.BigEndian.Uint64(b[8*i:])
		if a1 != b1 {
			return a1 < b1
		}
	}
	return false
}

func calculateAcctsDeltaHash(accts []*accounts.Account) []byte {
	acctHashes := calculateAccountHashes(accts)

	// sort by pubkey
	sort.SliceStable(acctHashes, func(i, j int) bool {
		return pubkeyCmp(acctHashes[i].Pubkey, acctHashes[j].Pubkey)
	})

	hashes := make([][]byte, len(acctHashes))
	for idx, ah := range acctHashes {
		hashes[idx] = make([]byte, 32)
		copy(hashes[idx], ah.Hash[:])
	}

	return computeMerkleRootLoop(hashes)
}

func calculateBankHash(acctsDeltaHash []byte, parentBankHash [32]byte, numSigs uint64, blockHash [32]byte) []byte {
	hasher := sha256.New()
	hasher.Write(parentBankHash[:])
	hasher.Write(acctsDeltaHash[:])

	var numSigsBytes [8]byte
	binary.LittleEndian.PutUint64(numSigsBytes[:], numSigs)

	hasher.Write(numSigsBytes[:])
	hasher.Write(blockHash[:])

	return hasher.Sum(nil)
}
