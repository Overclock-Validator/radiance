package sealevel

import (
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
)

type Authorized struct {
	Staker     solana.PublicKey
	Withdrawer solana.PublicKey
}

type StakeLockup struct {
	UnixTimeStamp uint64
	Epoch         uint64
	Custodian     solana.PublicKey
}

func (authorized *Authorized) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	pk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(authorized.Staker[:], pk)

	pk, err = decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(authorized.Withdrawer[:], pk)
	return nil
}

func (lockup *StakeLockup) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	lockup.UnixTimeStamp, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	lockup.Epoch, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	pk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(lockup.Custodian[:], pk)

	return nil
}
