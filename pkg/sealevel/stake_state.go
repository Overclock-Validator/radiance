package sealevel

import (
	"bytes"
	"math"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/safemath"
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
	StakeLamports      uint64
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

type StakeConfig struct {
	WarmupCooldownRate float64
	SlashPenalty       byte
}

const (
	StakeStateV2StatusUninitialized = iota
	StakeStateV2StatusInitialized
	StakeStateV2StatusStake
	StakeStateV2StatusRewardsPool
)

const (
	StakeAuthorizeStaker = iota
	StakeAuthorizeWithdrawer
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

func (authorized *Authorized) Check(signers []solana.PublicKey, stakeAuthorize uint32) error {
	switch stakeAuthorize {
	case StakeAuthorizeStaker:
		{
			err := verifySigner(authorized.Withdrawer, signers)
			if err != nil {
				return InstrErrMissingRequiredSignature
			} else {
				return nil
			}
		}

	case StakeAuthorizeWithdrawer:
		{
			err := verifySigner(authorized.Withdrawer, signers)
			if err != nil {
				return InstrErrMissingRequiredSignature
			} else {
				return nil
			}
		}

	default:
		{
			panic("shouldn't be possible")
		}
	}

}

func (authorized *Authorized) Authorize(signers []solana.PublicKey, newAuthorized solana.PublicKey, stakeAuthorize uint32, lockup StakeLockup, clock SysvarClock, custodian *solana.PublicKey) error {

	switch stakeAuthorize {
	case StakeAuthorizeStaker:
		{
			err1 := verifySigner(authorized.Staker, signers)
			err2 := verifySigner(authorized.Withdrawer, signers)

			if err1 != nil && err2 != nil {
				return InstrErrMissingRequiredSignature
			}

			authorized.Staker = newAuthorized
		}

	case StakeAuthorizeWithdrawer:
		{
			if lockup.IsInForce(clock, nil) {
				if custodian == nil {
					return StakeErrCustodianMissing
				} else {
					err := verifySigner(*custodian, signers)
					if err != nil {
						return StakeErrCustodianSignatureMissing
					}

					if lockup.IsInForce(clock, custodian) {
						return StakeErrLockupInForce
					}
				}
			}

			err := authorized.Check(signers, stakeAuthorize)
			if err != nil {
				return err
			}

			authorized.Withdrawer = newAuthorized
		}

	default:
		{
			panic("shouldn't be possible")
		}
	}

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

func (lockup *StakeLockup) IsInForce(clock SysvarClock, custodian *solana.PublicKey) bool {
	if custodian != nil && *custodian == lockup.Custodian {
		return false
	}

	return lockup.UnixTimeStamp > uint64(clock.UnixTimestamp) || lockup.Epoch > clock.Epoch
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

	delegation.StakeLamports, err = decoder.ReadUint64(bin.LE)
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

	err = encoder.WriteUint64(delegation.StakeLamports, bin.LE)
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

func (delegation *Delegation) Stake(epoch uint64, stakeHistory SysvarStakeHistory, newRateActivationEpoch *uint64) uint64 {
	return delegation.StakeActivatingAndDeactivating(epoch, stakeHistory, newRateActivationEpoch).Effective
}

func (delegation *Delegation) IsBootstrap() bool {
	return delegation.ActivationEpoch == math.MaxUint64
}

func (delegation *Delegation) StakeAndActivating(targetEpoch uint64, stakeHistory SysvarStakeHistory, newRateActivationEpoch *uint64) (uint64, uint64) {
	delegatedStake := delegation.StakeLamports

	if delegation.IsBootstrap() {
		return delegatedStake, 0
	} else if delegation.ActivationEpoch == delegation.DeactivationEpoch {
		return 0, 0
	} else if targetEpoch == delegation.ActivationEpoch {
		return 0, delegatedStake
	} else if targetEpoch < delegation.ActivationEpoch {
		return 0, 0
	} else if prevClusterStake := stakeHistory.Get(delegation.ActivationEpoch); prevClusterStake != nil {
		prevEpoch := delegation.ActivationEpoch
		currentEpoch := uint64(0)
		currentEffectiveStake := uint64(0)

		for {
			currentEpoch = prevEpoch + 1

			if prevClusterStake.Activating == 0 {
				break
			}

			remainingActivatingStake := delegatedStake - currentEffectiveStake
			weight := float64(remainingActivatingStake) / float64(prevClusterStake.Activating)
			warmupCooldownRate := warmupCooldownRate(currentEpoch, newRateActivationEpoch)

			newlyEffectiveClusterStake := float64(prevClusterStake.Effective) * warmupCooldownRate

			var newlyEffectiveStake uint64
			if uint64(weight*newlyEffectiveClusterStake) < 1 {
				newlyEffectiveStake = 1
			} else {
				newlyEffectiveStake = uint64(weight * newlyEffectiveClusterStake)
			}

			currentEffectiveStake += newlyEffectiveStake
			if currentEffectiveStake >= delegatedStake {
				currentEffectiveStake = delegatedStake
				break
			}

			if currentEpoch >= targetEpoch || currentEpoch >= delegation.DeactivationEpoch {
				break
			}

			if currentClusterStake := stakeHistory.Get(currentEpoch); currentClusterStake != nil {
				prevEpoch = currentEpoch
				prevClusterStake = currentClusterStake
			} else {
				break
			}
		}
		return currentEffectiveStake, (delegatedStake - currentEffectiveStake)
	} else {
		return delegatedStake, 0
	}
}

func (delegation *Delegation) StakeActivatingAndDeactivating(targetEpoch uint64, stakeHistory SysvarStakeHistory, newRateActivationEpoch *uint64) StakeHistoryEntry {
	effectiveStake, activatingStake := delegation.StakeAndActivating(targetEpoch, stakeHistory, newRateActivationEpoch)

	if targetEpoch < delegation.DeactivationEpoch {
		if activatingStake == 0 {
			return StakeHistoryEntry{Effective: effectiveStake}
		} else {
			return StakeHistoryEntry{Effective: effectiveStake, Activating: activatingStake}
		}
	} else if targetEpoch == delegation.DeactivationEpoch {
		return StakeHistoryEntry{Deactivating: effectiveStake}
	} else if prevClusterStake := stakeHistory.Get(delegation.DeactivationEpoch); prevClusterStake != nil {
		prevEpoch := delegation.DeactivationEpoch
		currentEpoch := uint64(0)
		currentEffectiveStake := effectiveStake

		for {
			currentEpoch = prevEpoch + 1

			if prevClusterStake.Deactivating == 0 {
				break
			}

			weight := float64(currentEffectiveStake) / float64(prevClusterStake.Deactivating)
			warmupCooldownRate := warmupCooldownRate(currentEpoch, newRateActivationEpoch)

			newlyNotEffectiveClusterStake := float64(prevClusterStake.Effective) * warmupCooldownRate

			var newlyNotEffectiveStake uint64
			if (weight * newlyNotEffectiveClusterStake) > 1 {
				newlyNotEffectiveStake = 1
			} else {
				newlyNotEffectiveStake = uint64(weight * newlyNotEffectiveClusterStake)
			}

			currentEffectiveStake = safemath.SaturatingSubU64(currentEffectiveStake, newlyNotEffectiveStake)
			if currentEffectiveStake == 0 {
				break
			}

			if currentEpoch >= targetEpoch {
				break
			}

			if currentClusterStake := stakeHistory.Get(currentEpoch); currentClusterStake != nil {
				prevEpoch = currentEpoch
				prevClusterStake = currentClusterStake
			} else {
				break
			}
		}
		return StakeHistoryEntry{Deactivating: currentEffectiveStake}
	} else {
		return StakeHistoryEntry{}
	}
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

func (stake *Stake) Stake(epoch uint64, stakeHistory SysvarStakeHistory, newRateActivationEpoch *uint64) uint64 {
	return stake.Delegation.Stake(epoch, stakeHistory, newRateActivationEpoch)
}

func (stake *Stake) Split(remainingStakeDelta uint64, splitStakeAmount uint64) (Stake, error) {
	if remainingStakeDelta > stake.Delegation.StakeLamports {
		return Stake{}, StakeErrInsufficientStake
	}
	stake.Delegation.StakeLamports -= remainingStakeDelta

	stakeObj := *stake
	newStake := stakeObj
	newStake.Delegation.StakeLamports = splitStakeAmount
	return newStake, nil
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

func (config *StakeConfig) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	config.WarmupCooldownRate, err = decoder.ReadFloat64(bin.LE)
	if err != nil {
		return err
	}

	config.SlashPenalty, err = decoder.ReadByte()
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

func unmarshalStakeConfig(data []byte) (*StakeConfig, error) {
	decoder := bin.NewBinDecoder(data)

	config := new(StakeConfig)
	err := config.UnmarshalWithDecoder(decoder)
	if err != nil {
		return nil, err
	} else {
		return config, nil
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

func newWarmupCooldownRateEpoch(execCtx *ExecutionCtx) *uint64 {
	f := execCtx.GlobalCtx.Features
	slot, existed := f.ActivationSlot(features.ReduceStakeWarmupCooldown)
	if !existed {
		return nil
	}

	epochSchedule := ReadEpochScheduleSysvar(&execCtx.Accounts)

	epoch := epochSchedule.GetEpoch(slot)
	return &epoch
}

func modifyStakeForRedelegation(execCtx *ExecutionCtx, stake *Stake, stakeLamports uint64, voterPubkey solana.PublicKey, voteState *VoteState, clock SysvarClock, stakeHistory SysvarStakeHistory) error {
	newRateActivationEpoch := newWarmupCooldownRateEpoch(execCtx)

	if stake.Stake(clock.Epoch, stakeHistory, newRateActivationEpoch) != 0 {
		var stakeLamportsOk bool
		if execCtx.GlobalCtx.Features.IsActive(features.StakeRedelegateInstruction) {
			stakeLamportsOk = stakeLamports >= stake.Delegation.StakeLamports
		} else {
			stakeLamportsOk = true
		}
		if stake.Delegation.VoterPubkey == voterPubkey &&
			clock.Epoch == stake.Delegation.DeactivationEpoch && stakeLamportsOk {
			stake.Delegation.DeactivationEpoch = math.MaxUint64
			return nil
		} else {
			return StakeErrTooSoonToRedelegate
		}
	}

	stake.Delegation.StakeLamports = stakeLamports
	stake.Delegation.ActivationEpoch = clock.Epoch
	stake.Delegation.DeactivationEpoch = math.MaxUint64
	stake.Delegation.VoterPubkey = voterPubkey
	stake.CreditsObserved = voteState.Credits()
	return nil
}
