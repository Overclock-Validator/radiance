package sealevel

import (
	"errors"
	"math"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/safemath"
)

const (
	StakeStateV2Size = 200
)

const (
	StakeProgramInstrTypeInitialize = iota
	StakeProgramInstrTypeAuthorize
	StakeProgramInstrTypeDelegateStake
	StakeProgramInstrTypeSplit
	StakeProgramInstrTypeWithdraw
	StakeProgramInstrTypeDeactivate
	StakeprogramInstrTypeSetLockup
	StakeProgramInstrTypeMerge
	StakeProgramInstrTypeAuthorizeWithSeed
	StakeProgramInstrTypeInitializeChecked
	StakeProgramInstrTypeAuthorizeChecked
	StakeProgramInstrTypeAuthorizeCheckedWithSeed
	StakeProgramInstrTypeSetLockupChecked
	StakeProgramInstrTypeGetMinimumDelegation
	StakeProgramInstrTypeDeactivateDelinquent
	StakeProgramInstrTypeRedelegate
)

// stake errors
var (
	StakeErrCustodianMissing          = errors.New("StakeErrCustodianMissing")
	StakeErrCustodianSignatureMissing = errors.New("StakeErrCustodianSignatureMissing")
	StakeErrLockupInForce             = errors.New("StakeErrLockupInForce")
	StakeErrInsufficientDelegation    = errors.New("StakeErrInsufficientDelegation")
	StakeErrTooSoonToRedelegate       = errors.New("StakeErrTooSoonToRedelegate")
)

type StakeInstrInitialize struct {
	Authorized Authorized
	Lockup     StakeLockup
}

type StakeInstrAuthorize struct {
	Pubkey         solana.PublicKey
	StakeAuthorize uint32
}

type StakeInstrSplit struct {
	Lamports uint64
}

type StakeInstrWithdraw struct {
	Lamports uint64
}

type StakeInstrSetLockup struct {
	UnixTimestamp *uint64
	Epoch         *uint64
	Custodian     *solana.PublicKey
}

type StakeInstrAuthorizeWithSeed struct {
	NewAuthorizedPubkey solana.PublicKey
	StakeAuthorize      uint32
	AuthoritySeed       string
	AuthorityOwner      solana.PublicKey
}

type StakeInstrAuthorizeChecked struct {
	StakeAuthorize uint32
}

type StakeInstrAuthorizeCheckedWithSeed struct {
	StakeAuthorize uint32
	AuthoritySeed  string
	AuthorityOwner solana.PublicKey
}

type StakeInstrSetLockupChecked struct {
	UnixTimestamp *uint64
	Epoch         *uint64
}

func (initialize *StakeInstrInitialize) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	err = initialize.Authorized.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}

	err = initialize.Lockup.UnmarshalWithDecoder(decoder)
	return err
}

func (auth *StakeInstrAuthorize) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	pk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(auth.Pubkey[:], pk)

	auth.StakeAuthorize, err = decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
	}

	if auth.StakeAuthorize != StakeAuthorizeStaker && auth.StakeAuthorize != StakeAuthorizeWithdrawer {
		return invalidEnumValue
	}

	return err
}

func (split *StakeInstrSplit) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	split.Lamports, err = decoder.ReadUint64(bin.LE)
	return err
}

func (withdraw *StakeInstrWithdraw) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	withdraw.Lamports, err = decoder.ReadUint64(bin.LE)
	return err
}

func (lockup *StakeInstrSetLockup) UnmarshalWithDecoder(decoder bin.Decoder) error {
	timeStampExists, err := decoder.ReadBool()
	if err != nil {
		return err
	}
	if timeStampExists {
		ts, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}
		lockup.UnixTimestamp = &ts
	}

	epochExists, err := decoder.ReadBool()
	if err != nil {
		return err
	}
	if epochExists {
		epoch, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}
		lockup.Epoch = &epoch
	}

	custodianExists, err := decoder.ReadBool()
	if err != nil {
		return err
	}
	if custodianExists {
		custodianPkBytes, err := decoder.ReadBytes(solana.PublicKeyLength)
		if err != nil {
			return err
		}

		pk := solana.PublicKeyFromBytes(custodianPkBytes)
		lockup.Custodian = &pk
	}

	return nil
}

func (authWithSeed *StakeInstrAuthorizeWithSeed) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	pk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(authWithSeed.NewAuthorizedPubkey[:], pk)

	authWithSeed.StakeAuthorize, err = decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
	}
	if authWithSeed.StakeAuthorize != StakeAuthorizeStaker && authWithSeed.StakeAuthorize != StakeAuthorizeWithdrawer {
		return invalidEnumValue
	}

	authWithSeed.AuthoritySeed, err = decoder.ReadRustString()
	if err != nil {
		return err
	}

	pk, err = decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(authWithSeed.AuthorityOwner[:], pk)
	return nil
}

func (authChecked *StakeInstrAuthorizeChecked) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	authChecked.StakeAuthorize, err = decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
	}

	if authChecked.StakeAuthorize != StakeAuthorizeStaker && authChecked.StakeAuthorize != StakeAuthorizeWithdrawer {
		return invalidEnumValue
	}

	return nil
}

func (authCheckedWithSeed *StakeInstrAuthorizeCheckedWithSeed) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	authCheckedWithSeed.StakeAuthorize, err = decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
	}
	if authCheckedWithSeed.StakeAuthorize != StakeAuthorizeStaker && authCheckedWithSeed.StakeAuthorize != StakeAuthorizeWithdrawer {
		return invalidEnumValue
	}

	authCheckedWithSeed.AuthoritySeed, err = decoder.ReadRustString()
	if err != nil {
		return err
	}

	pk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(authCheckedWithSeed.AuthorityOwner[:], pk)
	return nil
}

func (lockup *StakeInstrSetLockupChecked) UnmarshalWithDecoder(decoder bin.Decoder) error {
	timeStampExists, err := decoder.ReadBool()
	if err != nil {
		return err
	}
	if timeStampExists {
		ts, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}
		lockup.UnixTimestamp = &ts
	}

	epochExists, err := decoder.ReadBool()
	if err != nil {
		return err
	}
	if epochExists {
		epoch, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}
		lockup.Epoch = &epoch
	}

	return nil
}

func getOptionalPubkey(txCtx *TransactionCtx, instrCtx *InstructionCtx, instrAcctIdx uint64, mustBeSigner bool) (*solana.PublicKey, error) {
	if instrAcctIdx < instrCtx.NumberOfInstructionAccounts() {
		isSigner, err := instrCtx.IsInstructionAccountSigner(instrAcctIdx)
		if err != nil {
			return nil, err
		}

		if mustBeSigner && !isSigner {
			return nil, InstrErrMissingRequiredSignature
		}

		idxInTx, err := instrCtx.IndexOfInstructionAccountInTransaction(instrAcctIdx)
		if err != nil {
			return nil, err
		}

		pubkey, err := txCtx.KeyOfAccountAtIndex(idxInTx)
		if err != nil {
			return nil, err
		} else {
			return &pubkey, nil
		}
	} else { // no pubkey, not an error
		return nil, nil
	}
}

func StakeProgramExecute(execCtx *ExecutionCtx) error {
	err := execCtx.ComputeMeter.Consume(CUStakeProgramDefaultComputeUnits)
	if err != nil {
		return err
	}

	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	data := instrCtx.Data

	getStakeAccount := func() (*BorrowedAccount, error) {
		acct, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
		if err != nil {
			return nil, err
		}
		if acct.Owner() != StakeProgramAddr {
			return nil, InstrErrInvalidAccountOwner
		}
		return acct, nil
	}

	signers, err := instrCtx.Signers(txCtx)
	if err != nil {
		return err
	}

	decoder := bin.NewBinDecoder(data)
	instructionType, err := decoder.ReadUint32(bin.LE)
	if err != nil {
		return InstrErrInvalidInstructionData
	}

	switch instructionType {
	case StakeProgramInstrTypeInitialize:
		{
			var initialize StakeInstrInitialize
			err = initialize.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}

			me, err := getStakeAccount()
			if err != nil {
				return err
			}

			rent := ReadRentSysvar(&execCtx.Accounts)
			err = checkAcctForRentSysvar(txCtx, instrCtx, 1)
			if err != nil {
				return err
			}

			err = StakeProgramInitialize(me, initialize.Authorized, initialize.Lockup, rent, execCtx.GlobalCtx.Features)
		}

	case StakeProgramInstrTypeAuthorize:
		{
			var authorize StakeInstrAuthorize
			err = authorize.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}

			me, err := getStakeAccount()
			if err != nil {
				return err
			}

			clock := ReadClockSysvar(&execCtx.Accounts)
			err = checkAcctForClockSysvar(txCtx, instrCtx, 1)
			if err != nil {
				return err
			}

			err = instrCtx.CheckNumOfInstructionAccounts(3)
			if err != nil {
				return err
			}

			custodianPubkey, err := getOptionalPubkey(txCtx, instrCtx, 3, false)
			if err != nil {
				return err
			}

			err = StakeProgramAuthorize(me, signers, authorize.Pubkey, authorize.StakeAuthorize, clock, custodianPubkey, execCtx.GlobalCtx.Features)
		}

	case StakeProgramInstrTypeAuthorizeWithSeed:
		{
			var authorizeWithSeed StakeInstrAuthorizeWithSeed
			authorizeWithSeed.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}

			me, err := getStakeAccount()
			if err != nil {
				return err
			}

			err = instrCtx.CheckNumOfInstructionAccounts(2)
			if err != nil {
				return err
			}

			clock := ReadClockSysvar(&execCtx.Accounts)
			err = checkAcctForClockSysvar(txCtx, instrCtx, 1)
			if err != nil {
				return err
			}

			custodianPubkey, err := getOptionalPubkey(txCtx, instrCtx, 3, false)
			if err != nil {
				return err
			}

			err = StakeProgramAuthorizeWithSeed(txCtx, instrCtx, me, 1, authorizeWithSeed.AuthoritySeed, authorizeWithSeed.AuthorityOwner, authorizeWithSeed.NewAuthorizedPubkey, authorizeWithSeed.StakeAuthorize, clock, custodianPubkey, execCtx.GlobalCtx.Features)
		}

	case StakeProgramInstrTypeDelegateStake:
		{
			_, err := getStakeAccount()
			if err != nil {
				return err
			}

			err = instrCtx.CheckNumOfInstructionAccounts(2)
			if err != nil {
				return err
			}

			clock := ReadClockSysvar(&execCtx.Accounts)
			err = checkAcctForClockSysvar(txCtx, instrCtx, 2)
			if err != nil {
				return err
			}

			stakeHistory := ReadStakeHistorySysvar(&execCtx.Accounts)
			err = checkAcctForStakeHistorySysvar(txCtx, instrCtx, 3)
			if err != nil {
				return err
			}

			err = instrCtx.CheckNumOfInstructionAccounts(5)
			if err != nil {
				return err
			}

			if execCtx.GlobalCtx.Features.IsActive(features.ReduceStakeWarmupCooldown) {
				configAcct, err := instrCtx.BorrowInstructionAccount(txCtx, 4)
				if err != nil {
					return err
				}
				if configAcct.Key() != StakeProgramConfigAddr {
					return InstrErrInvalidArgument
				}

				_, err = unmarshalStakeConfig(configAcct.Data())
				if err != nil {
					return InstrErrInvalidArgument
				}
			}

			err = StakeProgramDelegate(execCtx, txCtx, instrCtx, 0, 1, clock, stakeHistory, signers, execCtx.GlobalCtx.Features)
		}
	}

	return err
}

func StakeProgramInitialize(stakeAcct *BorrowedAccount, authorized Authorized, lockup StakeLockup, rent SysvarRent, f features.Features) error {
	if len(stakeAcct.Data()) != StakeStateV2Size {
		return InstrErrInvalidAccountData
	}

	state, err := unmarshalStakeState(stakeAcct.Data())
	if err != nil {
		return err
	}

	if state.Status == StakeStateV2StatusUninitialized {
		rentExemptReserve := rent.MinimumBalance(uint64(len(stakeAcct.Data())))
		if stakeAcct.Lamports() >= rentExemptReserve {
			newStakeState := new(StakeStateV2)
			newStakeState.Status = StakeStateV2StatusInitialized
			newStakeState.Initialized = StakeStateV2Initialized{Meta: Meta{RentExemptReserve: rentExemptReserve, Authorized: authorized, Lockup: lockup}}
			return setStakeAccountState(stakeAcct, newStakeState, f)
		} else {
			return InstrErrInsufficientFunds
		}
	} else {
		return InstrErrInvalidAccountData
	}
}

func determineMinimumDelegation(f features.Features) uint64 {
	if f.IsActive(features.StakeRaiseMinimumDelegationTo1Sol) {
		minimumDelegationSol := 1
		lamportsPerSol := 1000000000
		return uint64(minimumDelegationSol * lamportsPerSol)
	} else {
		return 1
	}
}

func validateAndReturnDelegatedAmount(stakeAcct *BorrowedAccount, meta Meta, f features.Features) (uint64, error) {
	stakeAmount := safemath.SaturatingSubU64(stakeAcct.Lamports(), meta.RentExemptReserve)
	minimumDelegation := determineMinimumDelegation(f)

	if stakeAmount < minimumDelegation {
		return 0, StakeErrInsufficientDelegation
	}

	return stakeAmount, nil
}

func StakeProgramAuthorize(stakeAcct *BorrowedAccount, signers []solana.PublicKey, newAuthority solana.PublicKey, stakeAuthorize uint32, clock SysvarClock, custodianPubkey *solana.PublicKey, f features.Features) error {
	state, err := unmarshalStakeState(stakeAcct.Data())
	if err != nil {
		return err
	}

	switch state.Status {
	case StakeStateV2StatusStake:
		{
			err = state.Stake.Meta.Authorized.Authorize(signers, newAuthority, stakeAuthorize, state.Stake.Meta.Lockup, clock, custodianPubkey)
			if err != nil {
				return err
			}

			err = setStakeAccountState(stakeAcct, state, f)
		}

	case StakeStateV2StatusInitialized:
		{
			err = state.Initialized.Meta.Authorized.Authorize(signers, newAuthority, stakeAuthorize, state.Stake.Meta.Lockup, clock, custodianPubkey)
			if err != nil {
				return err
			}

			err = setStakeAccountState(stakeAcct, state, f)
		}

	default:
		{
			err = InstrErrInvalidAccountData
		}
	}

	return err
}

func StakeProgramAuthorizeWithSeed(txCtx *TransactionCtx, instrCtx *InstructionCtx, stakeAcct *BorrowedAccount, authorityBaseIndex uint64, authoritySeed string, authorityOwner solana.PublicKey, newAuthority solana.PublicKey, stakeAuthorize uint32, clock SysvarClock, custodian *solana.PublicKey, f features.Features) error {
	var signers []solana.PublicKey

	isSigner, err := instrCtx.IsInstructionAccountSigner(authorityBaseIndex)
	if err != nil {
		return err
	}

	if isSigner {
		idx, err := instrCtx.IndexOfInstructionAccountInTransaction(authorityBaseIndex)
		if err != nil {
			return err
		}

		basePubkey, err := txCtx.KeyOfAccountAtIndex(idx)
		if err != nil {
			return err
		}
		pk, err := solana.CreateWithSeed(basePubkey, authoritySeed, authorityOwner)
		if err != nil {
			return err
		}
		signers = append(signers, pk)
	}

	return StakeProgramAuthorize(stakeAcct, signers, newAuthority, stakeAuthorize, clock, custodian, f)
}

var DefaultWarmupCooldownRate float64 = 0.25
var NewWarmupCooldownRate float64 = 0.09

func warmupCooldownRate(currentEpoch uint64, newRateActivationEpoch *uint64) float64 {
	if newRateActivationEpoch == nil {
		e := uint64(math.MaxUint64)
		newRateActivationEpoch = &e
	}
	if currentEpoch < *newRateActivationEpoch {
		return DefaultWarmupCooldownRate
	} else {
		return NewWarmupCooldownRate
	}
}

func StakeProgramDelegate(execCtx *ExecutionCtx, txCtx *TransactionCtx, instrCtx *InstructionCtx, stakeAcctIdx uint64, voteAcctIdx uint64, clock SysvarClock, stakeHistory SysvarStakeHistory, signers []solana.PublicKey, f features.Features) error {
	voteAcct, err := instrCtx.BorrowInstructionAccount(txCtx, voteAcctIdx)
	if err != nil {
		return err
	}

	if voteAcct.Owner() != VoteProgramAddr {
		return InstrErrIncorrectProgramId
	}

	votePubkey := voteAcct.Key()
	versionedVoteState, voteUnmarshalErr := unmarshalVersionedVoteState(voteAcct.Data())

	stakeAcct, err := instrCtx.BorrowInstructionAccount(txCtx, stakeAcctIdx)
	if err != nil {
		return err
	}

	stakeState, err := unmarshalStakeState(stakeAcct.Data())
	if err != nil {
		return err
	}

	switch stakeState.Status {
	case StakeStateV2StatusInitialized:
		{
			err = stakeState.Initialized.Meta.Authorized.Check(signers, StakeAuthorizeStaker)
			if err != nil {
				return err
			}
			stakeAmount, err := validateAndReturnDelegatedAmount(stakeAcct, stakeState.Initialized.Meta, f)
			if err != nil {
				return err
			}

			if voteUnmarshalErr != nil {
				return voteUnmarshalErr
			}

			credits := versionedVoteState.ConvertToCurrent().Credits()
			stake := Stake{Delegation: Delegation{VoterPubkey: votePubkey, StakeLamports: stakeAmount, ActivationEpoch: clock.Epoch},
				CreditsObserved: credits}

			stakeState.Stake = StakeStateV2Stake{Meta: stakeState.Initialized.Meta, Stake: stake}
			err = setStakeAccountState(stakeAcct, stakeState, f)
			if err != nil {
				return err
			}
		}

	case StakeStateV2StatusStake:
		{
			err = stakeState.Stake.Meta.Authorized.Check(signers, StakeAuthorizeStaker)
			if err != nil {
				return err
			}
			stakeAmount, err := validateAndReturnDelegatedAmount(stakeAcct, stakeState.Stake.Meta, f)
			if err != nil {
				return err
			}

			if voteUnmarshalErr != nil {
				return voteUnmarshalErr
			}

			err = modifyStakeForRedelegation(execCtx, &stakeState.Stake.Stake, stakeAmount, votePubkey, versionedVoteState.ConvertToCurrent(), clock, stakeHistory)
			if err != nil {
				return err
			}

			err = setStakeAccountState(stakeAcct, stakeState, f)
			if err != nil {
				return err
			}
		}

	default:
		{
			return InstrErrInvalidAccountData
		}
	}

	return nil
}
