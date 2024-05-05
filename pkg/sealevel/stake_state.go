package sealevel

import (
	"bytes"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/features"
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

func (authorized *Authorized) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error
	err = encoder.WriteBytes(authorized.Staker[:], false)
	if err != nil {
		return err
	}

	err = encoder.WriteBytes(authorized.Withdrawer[:], false)
	return err
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

func (lockup *StakeLockup) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error
	err = encoder.WriteUint64(lockup.UnixTimeStamp, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(lockup.Epoch, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteBytes(lockup.Custodian[:], false)
	return err
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

func (meta *Meta) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error
	err = encoder.WriteUint64(meta.RentExemptReserve, bin.LE)
	if err != nil {
		return err
	}

	err = meta.Authorized.MarshalWithEncoder(encoder)
	if err != nil {
		return err
	}

	err = meta.Lockup.MarshalWithEncoder(encoder)
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

func (delegation *Delegation) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteBytes(delegation.VoterPubkey[:], false)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(delegation.Stake, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(delegation.ActivationEpoch, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(delegation.DeactivationEpoch, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteFloat64(delegation.WarmupCooldownRate, bin.LE)
	return err
}

func (stakeFlags *StakeFlags) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	stakeFlags.Bits, err = decoder.ReadByte()
	return err
}

func (stakeFlags *StakeFlags) MarshalWithEncoder(encoder *bin.Encoder) error {
	return encoder.WriteByte(stakeFlags.Bits)
}

func (initialized *StakeStateV2Initialized) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	err := initialized.Meta.UnmarshalWithDecoder(decoder)
	return err
}

func (initialized *StakeStateV2Initialized) MarshalWithEncoder(encoder *bin.Encoder) error {
	return initialized.MarshalWithEncoder(encoder)
}

func (stake *Stake) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	err := stake.Delegation.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}

	stake.CreditsObserved, err = decoder.ReadUint64(bin.LE)
	return err
}

func (stake *Stake) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error
	err = stake.Delegation.MarshalWithEncoder(encoder)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(stake.CreditsObserved, bin.LE)
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

func (stake *StakeStateV2Stake) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = stake.Meta.MarshalWithEncoder(encoder)
	if err != nil {
		return err
	}

	err = stake.Stake.MarshalWithEncoder(encoder)
	if err != nil {
		return err
	}

	err = stake.StakeFlags.MarshalWithEncoder(encoder)
	return err
}

func (state *StakeStateV2) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error

	state.Status, err = decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
	}

	switch state.Status {
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

func (state *StakeStateV2) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint32(state.Status, bin.LE)
	if err != nil {
		return err
	}

	switch state.Status {
	case StakeStateV2StatusUninitialized:
		{
			// nothing to serialize up
		}

	case StakeStateV2StatusInitialized:
		{
			err = state.Initialized.MarshalWithEncoder(encoder)
		}

	case StakeStateV2StatusStake:
		{
			err = state.Stake.MarshalWithEncoder(encoder)
		}

	case StakeStateV2StatusRewardsPool:
		{
			// nothing to serialize up
		}

	default:
		{
			panic("attempting to serialize up invalid stake state")
		}
	}

	return err
}

func unmarshalStakeState(data []byte) (*StakeStateV2, error) {
	state := new(StakeStateV2)
	decoder := bin.NewBinDecoder(data)

	err := state.UnmarshalWithDecoder(decoder)
	if err != nil {
		return nil, InstrErrInvalidAccountData
	} else {
		return state, nil
	}
}

func marshalStakeStake(state *StakeStateV2) ([]byte, error) {
	buffer := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(buffer)

	err := state.MarshalWithEncoder(encoder)
	if err != nil {
		return nil, err
	} else {
		return buffer.Bytes(), nil
	}
}

func setStakeAccountState(acct *BorrowedAccount, stakeState *StakeStateV2, f features.Features) error {
	stakeStateBytes, err := marshalStakeStake(stakeState)
	if err != nil {
		return err
	}

	err = acct.SetState(f, stakeStateBytes)
	return err
}
