package accounts

import (
	"io"

	"github.com/Overclock-Validator/mithril/pkg/base58"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
)

type Accounts interface {
	GetAccount(pubkey *[32]byte) (*Account, error)
	SetAccount(pubkey *[32]byte, acc *Account) error
	AllAccounts() []*Account
}

type Account struct {
	Slot       uint64
	Key        solana.PublicKey
	Lamports   uint64
	Data       []byte
	Owner      [32]byte
	Executable bool
	RentEpoch  uint64
}

// TODO: should probably be somewhere else
const NativeLoaderAddrStr = "NativeLoader1111111111111111111111111111111"

var NativeLoaderAddr = base58.MustDecodeFromString(NativeLoaderAddrStr)

func (a *Account) IsExecutable() bool {
	return a.Executable
}

func (a *Account) IsBuiltin() bool {
	return a.Owner == NativeLoaderAddr && len(a.Data) != 0
}

// have this placeholder setter to allow for locking/mutex later
func (a *Account) SetData(data []byte) {
	a.Data = data
}

func (a *Account) SetLamports(lamports uint64) {
	a.Lamports = lamports
}

func (a *Account) SetExecutable(isExecutable bool) {
	a.Executable = isExecutable
}

func (a *Account) Resize(newLen uint64, fillVal byte) {
	currentDataLen := uint64(len(a.Data))

	if newLen > currentDataLen { // extend, copy existing data, and fill the new excess with fillVal
		newData := make([]byte, newLen)
		copy(newData, a.Data)
		for count := uint64(currentDataLen); count < newLen; count++ {
			newData[count] = fillVal
		}
		a.Data = newData
	} else { // truncate
		a.Data = a.Data[:newLen]
	}
}

func (a *Account) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {
	a.Slot, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	var keyBytes []byte
	keyBytes, err = decoder.ReadNBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	a.Key = solana.PublicKeyFromBytes(keyBytes)

	a.Lamports, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}
	var dataLen uint64
	dataLen, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}
	if dataLen > uint64(decoder.Remaining()) {
		return io.ErrUnexpectedEOF
	}
	a.Data, err = decoder.ReadNBytes(int(dataLen))
	if err != nil {
		return err
	}

	var ownerBytes []byte
	ownerBytes, err = decoder.ReadNBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(a.Owner[:], ownerBytes)

	a.Executable, err = decoder.ReadBool()
	if err != nil {
		return err
	}

	a.RentEpoch, err = decoder.ReadUint64(bin.LE)
	return err
}

func (a *Account) MarshalWithEncoder(encoder *bin.Encoder) error {
	_ = encoder.WriteUint64(a.Slot, bin.LE)
	_ = encoder.WriteBytes(a.Key[:], false)
	_ = encoder.WriteUint64(a.Lamports, bin.LE)
	_ = encoder.WriteUint64(uint64(len(a.Data)), bin.LE)
	_ = encoder.WriteBytes(a.Data, false)
	_ = encoder.WriteBytes(a.Owner[:], false)
	_ = encoder.WriteBool(a.Executable)
	return encoder.WriteUint64(a.RentEpoch, bin.LE)
}
