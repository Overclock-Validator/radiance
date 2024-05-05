package sealevel

import (
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/features"
	"k8s.io/klog/v2"
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
	return err
}

func (authCheckedWithSeed *StakeInstrAuthorizeCheckedWithSeed) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	authCheckedWithSeed.StakeAuthorize, err = decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
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

	me, err := getStakeAccount()
	if err != nil {
		return err
	}

	klog.Infof("stake program execute, instruction data: %#v, stake acct: %#v", data, me)

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

			rent := ReadRentSysvar(&execCtx.Accounts)
			err = checkAcctForRentSysvar(txCtx, instrCtx, 1)
			if err != nil {
				return err
			}

			err = StakeProgramInitialize(me, initialize.Authorized, initialize.Lockup, rent, execCtx.GlobalCtx.Features)
		}
	}

	return nil
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
