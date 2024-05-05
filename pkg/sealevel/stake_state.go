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

type Meta struct {
	RentExemptReserve uint64
	Authorized        Authorized
	Lockup            StakeLockup
}

type Delegation struct {
	VoterPubkey        solana.PublicKey
	Stake              uint64
	ActivationEpoch    uint64
	DeactivationEpoch  uint64
	WarmupCooldownRate float64
}

type StakeFlags struct {
	Bits byte
}

type Stake struct {
	Delegation      Delegation
	CreditsObserved uint64
}

const (
	StakeStateV2StatusUninitialized = iota
	StakeStateV2StatusInitialized
	StakeStateV2StatusStake
	StakeStateV2StatusRewardsPool
)

type StakeStateV2Initialized struct {
	Meta Meta
}
type StakeStateV2Stake struct {
	Meta       Meta
	Stake      Stake
	StakeFlags StakeFlags
}

type StakeStateV2 struct {
	Status      uint32
	Initialized StakeStateV2Initialized
	Stake       StakeStateV2Stake
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

func (meta *Meta) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	meta.RentExemptReserve, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	err = meta.Authorized.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}

	err = meta.Lockup.UnmarshalWithDecoder(decoder)
	return err
}

func (delegation *Delegation) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	voterPubkey, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(delegation.VoterPubkey[:], voterPubkey)

	delegation.Stake, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	delegation.ActivationEpoch, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	delegation.DeactivationEpoch, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	delegation.WarmupCooldownRate, err = decoder.ReadFloat64(bin.LE)
	return err
}

func (stakeFlags *StakeFlags) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	stakeFlags.Bits, err = decoder.ReadByte()
	return err
}

func (initialized *StakeStateV2Initialized) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	err := initialized.Meta.UnmarshalWithDecoder(decoder)
	return err
}

func (stake *Stake) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	err := stake.Delegation.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}

	stake.CreditsObserved, err = decoder.ReadUint64(bin.LE)
	return err
}

func (stake *StakeStateV2Stake) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	err := stake.Meta.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}

	err = stake.Stake.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}

	err = stake.StakeFlags.UnmarshalWithDecoder(decoder)
	return err
}

func (state *StakeStateV2) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	status, err := decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
	}

	switch status {
	case StakeStateV2StatusUninitialized:
		{
			// nothing to deserialize
		}

	case StakeStateV2StatusInitialized:
		{
			err = state.Initialized.UnmarshalWithDecoder(decoder)
		}

	case StakeStateV2StatusStake:
		{
			err = state.Stake.UnmarshalWithDecoder(decoder)
		}

	case StakeStateV2StatusRewardsPool:
		{
			// nothing to deserialize
		}

	default:
		{
			err = InstrErrInvalidInstructionData
		}
	}

	return err
}
