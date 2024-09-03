package snapshot

import (
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/util"
)

const hdrLen = 136

type AppendVecAcctHeader struct {
	WriteVersion uint64
	DataLen      uint64
	Pubkey       solana.PublicKey
	Lamports     uint64
	RentEpoch    uint64
	Owner        solana.PublicKey
	Executable   bool
	Padding      [7]byte
	Hash         [32]byte
	Data         []byte
}

func (acctHdr *AppendVecAcctHeader) Unmarshal(data []byte) (uint64, error) {
	var offset uint64

	acctHdr.WriteVersion = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	acctHdr.DataLen = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	acctHdr.Pubkey = solana.PublicKeyFromBytes(data[offset:])
	offset += solana.PublicKeyLength

	acctHdr.Lamports = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	acctHdr.RentEpoch = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	acctHdr.Owner = solana.PublicKeyFromBytes(data[offset:])
	offset += solana.PublicKeyLength

	acctHdr.Executable = data[offset] == 1
	offset++

	for count := uint64(0); count < 7; count++ {
		acctHdr.Padding[count] = data[offset]
		offset++
	}

	copy(acctHdr.Hash[:], data[offset:])
	offset += 32

	if offset != hdrLen {
		panic(fmt.Sprintf("error, offset = %d and should be hdrLen %d", offset, hdrLen))
	}

	if acctHdr.DataLen == 0 {
		return offset, nil
	}

	if (uint64(len(data)) - offset) < acctHdr.DataLen {
		return 0, fmt.Errorf("not enough data for %x byte, acct data len %d", acctHdr.DataLen, uint64(len(data))-offset)
	}

	acctHdr.Data = make([]byte, acctHdr.DataLen)
	copy(acctHdr.Data, data[offset:])

	offset += acctHdr.DataLen
	offset = util.AlignUp(offset, 8)

	return offset, nil
}

func (acctHdr *AppendVecAcctHeader) ToAccount() *accounts.Account {
	return &accounts.Account{Key: acctHdr.Pubkey, Lamports: acctHdr.Lamports,
		Data: acctHdr.Data, Owner: acctHdr.Owner, Executable: acctHdr.Executable,
		RentEpoch: acctHdr.RentEpoch}
}

func UnmarshalAccountsFromAppendVecs(data []byte, appendVecInfo SlotAcctVecs) ([]*accounts.Account, error) {
	fileSize := appendVecInfo.AcctVecs[0].FileSize
	appendVecBytes := data

	acctHdrs := make([]*AppendVecAcctHeader, 0)
	var offset uint64

	for {
		if offset+hdrLen >= fileSize {
			break
		}

		input := appendVecBytes[offset:]

		if uint64(len(input)) < hdrLen {
			break
		}

		acct := new(AppendVecAcctHeader)
		bytesReadAligned, err := acct.Unmarshal(input)
		if err != nil {
			return nil, err
		}

		offset += bytesReadAligned

		acctHdrs = append(acctHdrs, acct)
	}

	accts := make([]*accounts.Account, 0)
	for _, acct := range acctHdrs {
		a := acct.ToAccount()
		accts = append(accts, a)
	}

	return accts, nil
}
