package replay

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/Overclock-Validator/mithril/pkg/accounts"
	"github.com/Overclock-Validator/mithril/pkg/safemath"
	"github.com/Overclock-Validator/mithril/pkg/sealevel"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/zeebo/blake3"
	"k8s.io/klog/v2"
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

	h := sha256.New()
	h.Write(acct.Data)

	//fmt.Printf("acct: pubkey %s, lamports %d, owner %s, rent_epoch %d, data hash: %s\n", acct.Key, acct.Lamports, solana.PublicKeyFromBytes(acct.Owner[:]), acct.RentEpoch, solana.HashFromBytes(h.Sum(nil)))

	return newAcctHash(acct.Key, hasher.Sum(nil))
}

func calculateAccountHashes(accts []*accounts.Account) []acctHash {
	pairs := make([]acctHash, 0)
	for _, acct := range accts {
		if acct.Lamports == 0 {
			pairs = append(pairs, newAcctHash(acct.Key, nil))
		} else {
			pair := calculateSingleAcctHash(*acct)
			pairs = append(pairs, pair)
		}
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

	fmt.Printf("accounts modified, sorted by pubkey:\n")
	for _, ah := range acctHashes {
		fmt.Printf("pubkey: %s, hash: %s\n", ah.Pubkey, solana.PublicKeyFromBytes(ah.Hash[:]))
	}

	hashes := make([][]byte, len(acctHashes))
	for idx, ah := range acctHashes {
		hashes[idx] = make([]byte, 32)
		copy(hashes[idx], ah.Hash[:])
	}

	return computeMerkleRootLoop(hashes)
}

const maxLockoutHistory = 31
const calculateIntervalBuffer = 150
const minimumCalculationInterval = maxLockoutHistory + calculateIntervalBuffer

func isEnabledThisEpoch(epochSchedule *sealevel.SysvarEpochSchedule, epoch uint64) bool {
	slotsPerEpoch := epochSchedule.SlotsInEpoch(epoch)
	calculationOffsetStart := slotsPerEpoch / 4
	calculationOffsetStop := (slotsPerEpoch / 4) * 3
	calculationInterval := safemath.SaturatingSubU64(calculationOffsetStop, calculationOffsetStart)

	return calculationInterval >= minimumCalculationInterval
}

func shouldIncludeEah(epochSchedule *sealevel.SysvarEpochSchedule, slotCtx *sealevel.SlotCtx) bool {
	if !isEnabledThisEpoch(epochSchedule, slotCtx.Epoch) {
		return false
	}

	slotsPerEpoch := epochSchedule.SlotsInEpoch(slotCtx.Epoch)
	calculationOffsetStop := (slotsPerEpoch / 4) * 3
	firstSlotInEpoch := epochSchedule.FirstSlotInEpoch(slotCtx.Epoch)
	stopSlot := safemath.SaturatingAddU64(firstSlotInEpoch, calculationOffsetStop)

	return slotCtx.ParentSlot < stopSlot && slotCtx.Slot >= stopSlot
}

func calculateBankHash(slotCtx *sealevel.SlotCtx, acctsDeltaHash []byte, parentBankHash [32]byte, numSigs uint64, blockHash [32]byte) []byte {
	hasher := sha256.New()
	hasher.Write(parentBankHash[:])
	hasher.Write(acctsDeltaHash[:])

	var numSigsBytes [8]byte
	binary.LittleEndian.PutUint64(numSigsBytes[:], numSigs)

	hasher.Write(numSigsBytes[:])
	hasher.Write(blockHash[:])

	bankHash := hasher.Sum(nil)

	epochScheduleAcct, err := slotCtx.Accounts.GetAccount(&sealevel.SysvarEpochScheduleAddr)
	if err != nil {
		panic("unable to get epochschedule sysvar acct")
	}

	dec := bin.NewBinDecoder(epochScheduleAcct.Data)
	var epochSchedule sealevel.SysvarEpochSchedule
	err = epochSchedule.UnmarshalWithDecoder(dec)
	if err != nil {
		panic("unable to deserialize epochschedule sysvar")
	}

	if shouldIncludeEah(&epochSchedule, slotCtx) {
		klog.Infof("**** EAH required for this bankhash")
	}

	return bankHash
}
