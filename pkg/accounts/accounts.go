package accounts

import (
	"io"

	bin "github.com/gagliardetto/binary"
)

type Accounts interface {
	GetAccount(pubkey *[32]byte) (*Account, error)
	SetAccount(pubkey *[32]byte, acc *Account) error
}

type Account struct {
	Lamports   uint64
	Data       []byte
	Owner      [32]byte
	Executable bool
	RentEpoch  uint64
}

func (a *Account) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {
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
	if err = decoder.Decode(&a.Owner); err != nil {
		return err
	}
	a.Executable, err = decoder.ReadBool()
	if err != nil {
		return err
	}
	a.RentEpoch, err = decoder.ReadUint64(bin.LE)
	return
}

func (a *Account) MarshalWihEncoder(encoder *bin.Encoder) error {
	_ = encoder.WriteUint64(a.Lamports, bin.LE)
	_ = encoder.WriteUint64(uint64(len(a.Data)), bin.LE)
	_ = encoder.WriteBytes(a.Data, false)
	_ = encoder.WriteBytes(a.Owner[:], false)
	_ = encoder.WriteBool(a.Executable)
	return encoder.WriteUint64(a.RentEpoch, bin.LE)
}
