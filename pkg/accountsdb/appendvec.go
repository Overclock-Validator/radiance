package accountsdb

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/Overclock-Validator/mithril/pkg/accounts"
	"github.com/Overclock-Validator/mithril/pkg/util"
	"github.com/gagliardetto/solana-go"
)

type AppendVecAccount struct {
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

const (
	hdrLen        = 136
	dataLenOffset = 8
	pubkeyOffset  = 16
)

type appendVecParser struct {
	Buf      []byte
	FileSize uint64
	Offset   uint64

	FileId uint64
	Slot   uint64
}

func (parser *appendVecParser) ParseNextAcct() (solana.PublicKey, *AccountIndexEntry, error) {
	if parser.Offset+hdrLen > parser.FileSize {
		return solana.PublicKey{}, nil, fmt.Errorf("overflow")
	}

	dataLen := binary.LittleEndian.Uint64(parser.Buf[parser.Offset+dataLenOffset : parser.Offset+dataLenOffset+8])
	pubkey := solana.PublicKeyFromBytes(parser.Buf[parser.Offset+pubkeyOffset : parser.Offset+pubkeyOffset+32])

	entry := &AccountIndexEntry{Slot: parser.Slot, FileId: parser.FileId, Offset: parser.Offset}

	parser.Offset += hdrLen

	if parser.Offset+dataLen > parser.FileSize {
		return solana.PublicKey{}, nil, fmt.Errorf("overflow")
	}

	parser.Offset += util.AlignUp(dataLen, 8)

	return pubkey, entry, nil
}

// TODO: optimise by rewriting without binary.Read(), which uses fairly expensive reflection
func (acct *AppendVecAccount) Unmarshal(buf io.Reader) error {
	var err error

	err = binary.Read(buf, binary.LittleEndian, &acct.WriteVersion)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &acct.DataLen)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &acct.Pubkey)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &acct.Lamports)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &acct.RentEpoch)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &acct.Owner)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &acct.Executable)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &acct.Padding)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &acct.Hash)
	if err != nil {
		return err
	}

	acct.Data = make([]byte, acct.DataLen)
	err = binary.Read(buf, binary.LittleEndian, &acct.Data)

	return err
}

var padding [2048]byte

// TODO: optimise by rewriting without binary.Write(), which uses fairly expensive reflection
func (acct *AppendVecAccount) Marshal(buf io.Writer) error {
	var err error

	err = binary.Write(buf, binary.LittleEndian, &acct.WriteVersion)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.LittleEndian, &acct.DataLen)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.LittleEndian, &acct.Pubkey)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.LittleEndian, &acct.Lamports)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.LittleEndian, &acct.RentEpoch)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.LittleEndian, &acct.Owner)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.LittleEndian, &acct.Executable)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.LittleEndian, &acct.Padding)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.LittleEndian, &acct.Hash)
	if err != nil {
		return err
	}

	err = binary.Write(buf, binary.LittleEndian, &acct.Data)
	if err != nil {
		return err
	}

	numPaddingBytes := util.AlignUp(acct.DataLen, 8) - acct.DataLen
	n, err := buf.Write(padding[:numPaddingBytes])
	if err != nil {
		return err
	} else if n != int(numPaddingBytes) {
		return fmt.Errorf("number of padding bytes written was %d rather than %d", n, numPaddingBytes)
	}

	return nil
}

func (appendVecAcct *AppendVecAccount) ToAccount() *accounts.Account {
	acct := &accounts.Account{Key: appendVecAcct.Pubkey, Lamports: appendVecAcct.Lamports,
		RentEpoch: appendVecAcct.RentEpoch, Owner: appendVecAcct.Owner, Executable: appendVecAcct.Executable,
		Data: appendVecAcct.Data}

	return acct
}

func appendVecAcctsMarshaledSize(accts []*accounts.Account) uint64 {
	var size uint64
	for _, acct := range accts {
		size += hdrLen + util.AlignUp(uint64(len(acct.Data)), 8)
	}
	return size
}

func unmarshalAcctFromAppendVecAcctHeader(buf io.Reader) (*accounts.Account, error) {
	var appendVecAcct AppendVecAccount
	err := appendVecAcct.Unmarshal(buf)
	if err != nil {
		return nil, err
	}

	return appendVecAcct.ToAccount(), nil
}
