package sealevel

import (
	"bytes"
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
)

const SysvarSlotHashesAddrStr = "SysvarS1otHashes111111111111111111111111111"

var SysvarSlotHashesAddr = base58.MustDecodeFromString(SysvarSlotHashesAddrStr)

type SlotHash struct {
	Slot uint64
	Hash [32]byte
}

type SysvarSlotHashes []SlotHash

func (sh *SysvarSlotHashes) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {
	hashesLen, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read length of SlotHashes vec when decoding SysvarSlotHashes: %w", err)
	}

	slotHashes := *sh

	for count := 0; count < int(hashesLen); count++ {
		slot, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return fmt.Errorf("failed to read Slot when decoding a SlotHash in SysvarSlotHashes: %w", err)
		}
		hash, err := decoder.ReadBytes(32)
		if err != nil {
			return fmt.Errorf("failed to read Hash when decoding a SlotHash in SysvarSlotHashes: %w", err)
		}
		slotHash := SlotHash{}
		slotHash.Slot = slot
		copy(slotHash.Hash[:], hash)

		slotHashes = append(slotHashes, slotHash)
	}

	return
}

func (sh *SysvarSlotHashes) MustUnmarshalWithDecoder(decoder *bin.Decoder) {
	err := sh.UnmarshalWithDecoder(decoder)
	if err != nil {
		panic(err.Error())
	}
}

func ReadSlotHashesSysvar(accts *accounts.Accounts) SysvarSlotHashes {
	slotHashesSysvarAcct, err := (*accts).GetAccount(&SysvarSlotHashesAddr)
	if err != nil {
		panic("failed to read SlotHashes sysvar account")
	}

	dec := bin.NewBinDecoder(slotHashesSysvarAcct.Data)

	var slotHashes SysvarSlotHashes
	slotHashes.MustUnmarshalWithDecoder(dec)

	return slotHashes
}

func WriteSlotHashesSysvar(accts *accounts.Accounts, slotHashes SysvarSlotHashes) {

	slotHashesSysvarAcct, err := (*accts).GetAccount(&SysvarSlotHashesAddr)
	if err != nil {
		panic("failed to read EpochRewards sysvar account")
	}

	data := new(bytes.Buffer)
	enc := bin.NewBinEncoder(data)

	numSlotHashes := len(slotHashes)

	err = enc.WriteUint64(uint64(numSlotHashes), bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize len of SlotHashes for SlotHashes sysvar: %w", err)
		panic(err)
	}

	for count := 0; count < numSlotHashes; count++ {
		err = enc.WriteUint64(slotHashes[count].Slot, bin.LE)
		if err != nil {
			err = fmt.Errorf("failed to serialize Slot for SlotHashes sysvar: %w", err)
			panic(err)
		}

		enc.WriteBytes(slotHashes[count].Hash[:], false)
	}

	copy(slotHashesSysvarAcct.Data, data.Bytes())

	err = (*accts).SetAccount(&SysvarSlotHashesAddr, slotHashesSysvarAcct)
	if err != nil {
		err = fmt.Errorf("failed to write newly serialized SlotHashes sysvar to sysvar account: %w", err)
		panic(err)
	}
}
