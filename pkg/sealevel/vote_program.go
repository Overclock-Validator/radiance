package sealevel

import (
	"errors"
	"math"

	"github.com/edwingeng/deque/v2"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/safemath"
	"k8s.io/klog/v2"
)

const (
	VoteProgramInstrTypeInitializeAccount = iota
	VoteProgramInstrTypeAuthorize
	VoteProgramInstrTypeVote
	VoteProgramInstrTypeWithdraw
	VoteProgramInstrTypeUpdateValidatorIdentity
	VoteProgramInstrTypeUpdateCommission
	VoteProgramInstrTypeVoteSwitch
	VoteProgramInstrTypeAuthorizeChecked
	VoteProgramInstrTypeUpdateVoteState
	VoteProgramInstrTypeUpdateVoteStateSwitch
	VoteProgramInstrTypeAuthorizeWithSeed
	VoteProgramInstrTypeAuthorizeCheckedWithSeed
	VoteProgramInstrTypeCompactUpdateVoteState
	VoteProgramInstrTypeCompactUpdateVoteStateSwitch
)

var (
	VoteErrTooSoonToReauthorize    = errors.New("VoteErrTooSoonToReauthorize")
	VoteErrCommissionUpdateTooLate = errors.New("VoteErrCommissionUpdateTooLate")
	VoteErrEmptySlots              = errors.New("VoteErrEmptySlots")
	VoteErrVotesTooOldAllFiltered  = errors.New("VoteErrVotesTooOldAllFiltered")
	VoteErrVoteTooOld              = errors.New("VoteErrVoteTooOld")
	VoteErrSlotsMismatch           = errors.New("VoteErrSlotsMismatch")
	VoteErrSlotHashMismatch        = errors.New("VoteErrSlotHashMismatch")
	VoteErrTimestampTooOld         = errors.New("VoteErrTimestampTooOld")
)

type VoteInstrVoteInit struct {
	NodePubkey           solana.PublicKey
	AuthorizedVoter      solana.PublicKey
	AuthorizedWithdrawer solana.PublicKey
	Commission           byte
}

const (
	VoteAuthorizeTypeVoter = iota
	VoteAuthorizeTypeWithdrawer
)

type VoteInstrVoteAuthorize struct {
	Pubkey        solana.PublicKey
	VoteAuthorize uint32
}

type VoteInstrVote struct {
	Slots     []uint64
	Hash      [32]byte
	Timestamp *uint64
}

type VoteInstrWithdraw struct {
	Lamports uint64
}

type VoteInstrUpdateCommission struct {
	Commission byte
}

type VoteInstrVoteSwitch struct {
	Vote VoteInstrVote
	Hash [32]byte
}

type VoteInstrVoteAuthorizeChecked struct {
	Pubkey        solana.PublicKey
	VoteAuthorize uint32
}

type VoteInstrUpdateVoteState struct {
	Lockouts  deque.Deque[VoteLockout]
	Root      *uint64
	Hash      [32]byte
	Timestamp *uint64
}

type VoteInstrUpdateVoteStateSwitch struct {
	UpdateVoteState VoteInstrUpdateVoteState
	Hash            [32]byte
}

type VoteInstrAuthorizeWithSeed struct {
	AuthorizationType               uint32
	CurrentAuthorityDerivedKeyOwner solana.PublicKey
	CurrentAuthorityDerivedKeySeed  string
	NewAuthority                    solana.PublicKey
}

type VoteInstrAuthorizeCheckedWithSeed struct {
	AuthorizationType               uint32
	CurrentAuthorityDerivedKeyOwner solana.PublicKey
	CurrentAuthorityDerivedKeySeed  string
}

type LockoutOffset struct {
	Offset            uint64
	ConfirmationCount byte
}

type CompactUpdateVoteState struct {
	Root           uint64
	LockoutOffsets []LockoutOffset
	Hash           [32]byte
	Timestamp      *uint64
}

type VoteInstrCompactUpdateVoteState struct {
	UpdateVoteState VoteInstrUpdateVoteState
}

type VoteInstrCompactUpdateVoteStateSwitch struct {
	UpdateVoteState VoteInstrUpdateVoteState
	Hash            [32]byte
}

func (voteInit *VoteInstrVoteInit) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	nodePk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(voteInit.NodePubkey[:], nodePk)

	authVoter, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(voteInit.AuthorizedVoter[:], authVoter)

	authWithdrawer, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(voteInit.AuthorizedWithdrawer[:], authWithdrawer)

	voteInit.Commission, err = decoder.ReadByte()
	return err
}

func (voteAuthorize *VoteInstrVoteAuthorize) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	pk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(voteAuthorize.Pubkey[:], pk)

	voteAuthorize.VoteAuthorize, err = decoder.ReadUint32(bin.LE)
	return err
}

func (vote *VoteInstrVote) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	slotsLen, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	if slotsLen > 35 {
		return InstrErrInvalidInstructionData
	}

	for count := uint64(0); count < slotsLen; count++ {
		slot, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}
		vote.Slots = append(vote.Slots, slot)
	}

	hash, err := decoder.ReadBytes(32)
	if err != nil {
		return err
	}
	copy(vote.Hash[:], hash)

	hasTimestamp, err := decoder.ReadBool()
	if err != nil {
		return err
	}

	if hasTimestamp {
		timestamp, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}
		vote.Timestamp = &timestamp
	}
	return nil
}

func (withdraw *VoteInstrWithdraw) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	withdraw.Lamports, err = decoder.ReadUint64(bin.LE)
	return err
}

func (updateCommission *VoteInstrUpdateCommission) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	updateCommission.Commission, err = decoder.ReadByte()
	return err
}

func (voteSwitch *VoteInstrVoteSwitch) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	err := voteSwitch.Vote.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}

	hash, err := decoder.ReadBytes(32)
	if err != nil {
		return err
	}
	copy(voteSwitch.Hash[:], hash)
	return nil
}

func (voteAuthChecked *VoteInstrVoteAuthorizeChecked) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	pk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(voteAuthChecked.Pubkey[:], pk)

	voteAuthChecked.VoteAuthorize, err = decoder.ReadUint32(bin.LE)
	return err
}

func (updateVoteState *VoteInstrUpdateVoteState) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	numLockouts, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}
	if numLockouts > 1228 {
		return InstrErrInvalidInstructionData
	}

	for count := uint64(0); count < numLockouts; count++ {
		var lockout VoteLockout
		err = lockout.UnmarshalWithDecoder(decoder)
		if err != nil {
			return err
		}
		updateVoteState.Lockouts.PushBack(lockout)
	}

	hasRoot, err := decoder.ReadBool()
	if err != nil {
		return err
	}

	if hasRoot {
		root, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}
		updateVoteState.Root = &root
	}

	hash, err := decoder.ReadBytes(32)
	if err != nil {
		return err
	}
	copy(updateVoteState.Hash[:], hash)

	hasTimestamp, err := decoder.ReadBool()
	if err != nil {
		return err
	}

	if hasTimestamp {
		timestamp, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}
		updateVoteState.Timestamp = &timestamp
	}

	return nil
}

func (uvss *VoteInstrUpdateVoteStateSwitch) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	err := uvss.UpdateVoteState.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}

	hash, err := decoder.ReadBytes(32)
	if err != nil {
		return err
	}
	copy(uvss.Hash[:], hash)
	return nil
}

func (updateVoteState *VoteInstrUpdateVoteState) BuildFromCompactUpdateVoteState(compactUpdateVoteState *CompactUpdateVoteState) error {
	if compactUpdateVoteState.Root != math.MaxUint64 {
		updateVoteState.Root = &compactUpdateVoteState.Root
	}

	lockoutsLen := uint64(len(compactUpdateVoteState.LockoutOffsets))
	if lockoutsLen > 1228 {
		return InstrErrInvalidInstructionData
	}

	var slot uint64
	if updateVoteState.Root != nil {
		slot = *updateVoteState.Root
	}

	for _, lockoutOffset := range compactUpdateVoteState.LockoutOffsets {
		nextSlot, err := safemath.CheckedAddU64(slot, lockoutOffset.Offset)
		if err != nil {
			return InstrErrInvalidInstructionData
		}
		updateVoteState.Lockouts.PushBack(VoteLockout{Slot: nextSlot, ConfirmationCount: uint32(lockoutOffset.ConfirmationCount)})
	}

	updateVoteState.Hash = compactUpdateVoteState.Hash
	updateVoteState.Timestamp = compactUpdateVoteState.Timestamp

	return nil
}

func (compactUpdateVoteState *VoteInstrCompactUpdateVoteState) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var compactUpdate CompactUpdateVoteState
	err := compactUpdate.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}
	return compactUpdateVoteState.UpdateVoteState.BuildFromCompactUpdateVoteState(&compactUpdate)
}

func (compactUpdateVoteState *VoteInstrCompactUpdateVoteStateSwitch) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var compactUpdate CompactUpdateVoteState
	err := compactUpdate.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}
	err = compactUpdateVoteState.UpdateVoteState.BuildFromCompactUpdateVoteState(&compactUpdate)
	if err != nil {
		return err
	}
	hash, err := decoder.ReadBytes(32)
	if err != nil {
		return err
	}
	copy(compactUpdate.Hash[:], hash)
	return nil
}

func (authWithSeed *VoteInstrAuthorizeWithSeed) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	authWithSeed.AuthorizationType, err = decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
	}

	currentAuthorityDerivedKeyOwner, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(authWithSeed.CurrentAuthorityDerivedKeyOwner[:], currentAuthorityDerivedKeyOwner)

	authWithSeed.CurrentAuthorityDerivedKeySeed, err = decoder.ReadRustString()
	if err != nil {
		return err
	}

	newAuthority, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(authWithSeed.NewAuthority[:], newAuthority)

	return nil
}

func (acws *VoteInstrAuthorizeCheckedWithSeed) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	acws.AuthorizationType, err = decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
	}

	currentAuthorityDerivedKeyOwner, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(acws.CurrentAuthorityDerivedKeyOwner[:], currentAuthorityDerivedKeyOwner)

	acws.CurrentAuthorityDerivedKeySeed, err = decoder.ReadRustString()
	return err
}

func (lockoutOffset *LockoutOffset) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	lockoutOffset.Offset, err = decoder.ReadUvarint64()
	if err != nil {
		return err
	}

	lockoutOffset.ConfirmationCount, err = decoder.ReadByte()
	return err
}

func (cuvs *CompactUpdateVoteState) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	cuvs.Root, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	lockoutsLen, err := decoder.ReadCompactU16()
	if err != nil {
		return err
	}

	for count := 0; count < lockoutsLen; count++ {
		var lockoutOffset LockoutOffset
		err = lockoutOffset.UnmarshalWithDecoder(decoder)
		if err != nil {
			return err
		}
		cuvs.LockoutOffsets = append(cuvs.LockoutOffsets, lockoutOffset)
	}

	hash, err := decoder.ReadBytes(32)
	if err != nil {
		return err
	}
	copy(cuvs.Hash[:], hash)

	hasTimestamp, err := decoder.ReadBool()
	if hasTimestamp {
		timestamp, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}
		cuvs.Timestamp = &timestamp
	}
	return nil
}

func VoteProgramExecute(execCtx *ExecutionCtx) error {
	err := execCtx.ComputeMeter.Consume(CUVoteProgramDefaultComputeUnits)
	if err != nil {
		return err
	}

	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	me, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}

	if me.Owner() != solana.VoteProgramID {
		return InstrErrInvalidAccountOwner
	}

	signers, err := instrCtx.Signers(txCtx)
	if err != nil {
		return err
	}

	decoder := bin.NewBinDecoder(instrCtx.Data)

	instructionType, err := decoder.ReadUint32(bin.LE)
	if err != nil {
		return InstrErrInvalidInstructionData
	}

	var isVoteSwitch bool

	switch instructionType {
	case VoteProgramInstrTypeInitializeAccount:
		{
			var voteInit VoteInstrVoteInit
			err = voteInit.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}

			// TODO: switch to using a sysvar cache
			rent := ReadRentSysvar(&execCtx.Accounts)
			err = checkAcctForRentSysvar(txCtx, instrCtx, 1)
			if err != nil {
				return err
			}

			if !rent.IsExempt(me.Lamports(), uint64(len(me.Data()))) {
				return InstrErrInsufficientFunds
			}

			// TODO: switch to using a sysvar cache
			clock := ReadClockSysvar(&execCtx.Accounts)
			err = checkAcctForClockSysvar(txCtx, instrCtx, 2)
			if err != nil {
				return err
			}

			err = VoteProgramInitializeAccount(me, voteInit, signers, clock, execCtx.GlobalCtx.Features)
		}

	case VoteProgramInstrTypeAuthorize:
		{
			var voteAuthorize VoteInstrVoteAuthorize
			err = voteAuthorize.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}

			// TODO: switch to using a sysvar cache
			clock := ReadClockSysvar(&execCtx.Accounts)
			err = checkAcctForClockSysvar(txCtx, instrCtx, 1)
			if err != nil {
				return err
			}

			err = VoteProgramAuthorize(me, voteAuthorize.Pubkey, voteAuthorize.VoteAuthorize, signers, clock, execCtx.GlobalCtx.Features)
		}

	case VoteProgramInstrTypeAuthorizeWithSeed:
		{
			var voteAuthWithSeed VoteInstrAuthorizeWithSeed
			err = voteAuthWithSeed.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}

			err = instrCtx.CheckNumOfInstructionAccounts(3)
			if err != nil {
				return err
			}

			err = VoteProgramAuthorizeWithSeed(execCtx, instrCtx, me, voteAuthWithSeed.NewAuthority, voteAuthWithSeed.AuthorizationType, voteAuthWithSeed.CurrentAuthorityDerivedKeyOwner, voteAuthWithSeed.CurrentAuthorityDerivedKeySeed)
		}

	case VoteProgramInstrTypeAuthorizeCheckedWithSeed:
		{
			var voteAuthCheckedWithSeed VoteInstrAuthorizeCheckedWithSeed
			err = voteAuthCheckedWithSeed.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}

			err = instrCtx.CheckNumOfInstructionAccounts(4)
			if err != nil {
				return err
			}

			idx, err := instrCtx.IndexOfInstructionAccountInTransaction(3)
			if err != nil {
				return err
			}

			newAuthority, err := txCtx.KeyOfAccountAtIndex(idx)
			if err != nil {
				return err
			}

			isSigner, err := instrCtx.IsInstructionAccountSigner(3)
			if err != nil {
				return err
			}

			if !isSigner {
				return InstrErrMissingRequiredSignature
			}

			err = VoteProgramAuthorizeWithSeed(execCtx, instrCtx, me, newAuthority, voteAuthCheckedWithSeed.AuthorizationType, voteAuthCheckedWithSeed.CurrentAuthorityDerivedKeyOwner, voteAuthCheckedWithSeed.CurrentAuthorityDerivedKeySeed)
		}

	case VoteProgramInstrTypeUpdateValidatorIdentity:
		{
			err = instrCtx.CheckNumOfInstructionAccounts(2)
			if err != nil {
				return err
			}

			idx, err := instrCtx.IndexOfInstructionAccountInTransaction(1)
			if err != nil {
				return err
			}

			nodePubkey, err := txCtx.KeyOfAccountAtIndex(idx)
			if err != nil {
				return err
			}

			err = VoteProgramUpdateValidatorIdentity(me, nodePubkey, signers, execCtx.GlobalCtx.Features)
		}

	case VoteProgramInstrTypeUpdateCommission:
		{
			var updateCommission VoteInstrUpdateCommission
			err = updateCommission.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}

			// TODO: switch to using a sysvar cache
			clock := ReadClockSysvar(&execCtx.Accounts)
			epochSchedule := ReadEpochScheduleSysvar(&execCtx.Accounts)

			err = VoteProgramUpdateCommission(me, updateCommission.Commission, signers, epochSchedule, clock, execCtx.GlobalCtx.Features)
		}

	case VoteProgramInstrTypeVoteSwitch:
		isVoteSwitch = true
		fallthrough
	case VoteProgramInstrTypeVote:
		{
			var vote *VoteInstrVote
			if isVoteSwitch {
				var voteSwitch VoteInstrVoteSwitch
				err = voteSwitch.UnmarshalWithDecoder(decoder)
				if err != nil {
					return InstrErrInvalidInstructionData
				}
				vote = &voteSwitch.Vote
			} else {
				err = vote.UnmarshalWithDecoder(decoder)
				if err != nil {
					return InstrErrInvalidInstructionData
				}
			}

			// TODO: switch to using a sysvar cache

			slotHashes := ReadSlotHashesSysvar(&execCtx.Accounts)
			checkAcctForSlotHashesSysvar(txCtx, instrCtx, 1)

			clock := ReadClockSysvar(&execCtx.Accounts)
			err := checkAcctForClockSysvar(txCtx, instrCtx, 2)
			if err != nil {
				return err
			}

			err = VoteProgramProcessVote(me, slotHashes, clock, vote, signers, execCtx.GlobalCtx.Features)
		}
	}

	return err
}

func verifySigner(authorized solana.PublicKey, signers []solana.PublicKey) error {
	for _, signer := range signers {
		if signer == authorized {
			return nil
		}
	}
	return InstrErrMissingRequiredSignature
}

func VoteProgramInitializeAccount(voteAccount *BorrowedAccount, voteInit VoteInstrVoteInit, signers []solana.PublicKey, clock SysvarClock, f features.Features) error {
	if uint64(len(voteAccount.Data())) != sizeOfVersionedVoteState(f) {
		return InstrErrInvalidAccountData
	}

	versionedVoteState, err := unmarshalVersionedVoteState(voteAccount.Data())
	if err != nil {
		return err
	}

	if versionedVoteState.IsInitialized() {
		return InstrErrAccountAlreadyInitialized
	}

	err = verifySigner(voteInit.NodePubkey, signers)
	if err != nil {
		return err
	}

	voteState := newVoteStateFromVoteInit(voteInit, clock)
	return setVoteAccountState(voteAccount, voteState, f)
}

func VoteProgramAuthorize(voteAcct *BorrowedAccount, authorized solana.PublicKey, voteAuthorize uint32, signers []solana.PublicKey, clock SysvarClock, f features.Features) error {

	voteStateVersions, err := unmarshalVersionedVoteState(voteAcct.Data())
	if err != nil {
		return err
	}

	voteState := voteStateVersions.ConvertToCurrent()

	switch voteAuthorize {
	case VoteAuthorizeTypeVoter:
		{
			var authorizedWithDrawerSigner bool
			if verifySigner(voteState.AuthorizedWithdrawer, signers) == nil {
				authorizedWithDrawerSigner = true
			}

			err = voteState.SetNewAuthorizedVoter(authorized, clock.Epoch, clock.LeaderScheduleEpoch+1, func(epochAuthorizedVoter solana.PublicKey) error {
				if authorizedWithDrawerSigner {
					return nil
				} else {
					return verifySigner(epochAuthorizedVoter, signers)
				}
			})
			if err != nil {
				return err
			}
		}

	case VoteAuthorizeTypeWithdrawer:
		{
			err = verifySigner(voteState.AuthorizedWithdrawer, signers)
			if err != nil {
				return err
			}
			voteState.AuthorizedWithdrawer = authorized
		}
	}

	err = setVoteAccountState(voteAcct, voteState, f)
	return err
}

func VoteProgramAuthorizeWithSeed(execCtx *ExecutionCtx, instrCtx *InstructionCtx, voteAcct *BorrowedAccount, newAuthority solana.PublicKey, authorizationType uint32, currentAuthorityDerivedKeyOwner solana.PublicKey, currentAuthorityDerivedKeySeed string) error {
	txCtx := execCtx.TransactionContext

	// TODO: switch to using a sysvar cache
	clock := ReadClockSysvar(&execCtx.Accounts)
	err := checkAcctForClockSysvar(txCtx, instrCtx, 1)
	if err != nil {
		return err
	}

	var expectedAuthorityKeys []solana.PublicKey

	isSigner, err := instrCtx.IsInstructionAccountSigner(2)
	if err != nil {
		return err
	}

	if isSigner {
		idxInTx, err := instrCtx.IndexOfInstructionAccountInTransaction(2)
		if err != nil {
			return err
		}
		basePubkey, err := txCtx.KeyOfAccountAtIndex(idxInTx)
		if err != nil {
			return err
		}

		authKey, err := solana.CreateWithSeed(basePubkey, currentAuthorityDerivedKeySeed, currentAuthorityDerivedKeyOwner)
		if err != nil {
			return err
		}
		expectedAuthorityKeys = append(expectedAuthorityKeys, authKey)
	}

	err = VoteProgramAuthorize(voteAcct, newAuthority, authorizationType, expectedAuthorityKeys, clock, execCtx.GlobalCtx.Features)
	return err
}

func VoteProgramUpdateValidatorIdentity(voteAcct *BorrowedAccount, nodePubkey solana.PublicKey, signers []solana.PublicKey, f features.Features) error {
	voteStateVersions, err := unmarshalVersionedVoteState(voteAcct.Data())
	if err != nil {
		return err
	}

	voteState := voteStateVersions.ConvertToCurrent()

	err = verifySigner(voteState.AuthorizedWithdrawer, signers)
	if err != nil {
		return err
	}

	err = verifySigner(nodePubkey, signers)
	if err != nil {
		return err
	}

	voteState.NodePubkey = nodePubkey
	err = setVoteAccountState(voteAcct, voteState, f)

	return err
}

func isCommissionUpdateAllowed(slot uint64, epochSchedule SysvarEpochSchedule) bool {
	relativeSlot := safemath.SaturatingSubU64(slot, epochSchedule.FirstNormalSlot) % epochSchedule.SlotsPerEpoch
	return safemath.SaturatingMulU64(relativeSlot, 2) <= epochSchedule.SlotsPerEpoch
}

func VoteProgramUpdateCommission(voteAcct *BorrowedAccount, commission byte, signers []solana.PublicKey, epochSchedule SysvarEpochSchedule, clock SysvarClock, f features.Features) error {
	var voteState *VoteState

	var enforceCommissionUpdateRule bool
	if f.IsActive(features.AllowCommissionDecreaseAtAnyTime) {
		voteStateVersioned, err := unmarshalVersionedVoteState(voteAcct.Data())
		if err == nil { // successfully deserialized
			voteState = voteStateVersioned.ConvertToCurrent()
			if commission > voteState.Commission {
				enforceCommissionUpdateRule = true
			}
		} else { // failed to deserialize
			enforceCommissionUpdateRule = true
		}
	} else {
		enforceCommissionUpdateRule = true
	}

	if enforceCommissionUpdateRule && f.IsActive(features.CommissionUpdatesOnlyAllowedInFirstHalfOfEpoch) {
		if !isCommissionUpdateAllowed(clock.Slot, epochSchedule) {
			return VoteErrCommissionUpdateTooLate
		}
	}

	if voteState == nil {
		voteStateVersioned, err := unmarshalVersionedVoteState(voteAcct.Data())
		if err != nil {
			return err
		}
		voteState = voteStateVersioned.ConvertToCurrent()
	}

	err := verifySigner(voteState.AuthorizedWithdrawer, signers)
	if err != nil {
		return err
	}

	voteState.Commission = commission
	err = setVoteAccountState(voteAcct, voteState, f)

	return err
}

func verifyAndGetVoteState(voteAcct *BorrowedAccount, clock SysvarClock, signers []solana.PublicKey) (*VoteState, error) {
	versioned, err := unmarshalVersionedVoteState(voteAcct.Data())
	if err != nil {
		return nil, err
	}

	if !versioned.IsInitialized() {
		return nil, InstrErrUninitializedAccount
	}

	voteState := versioned.ConvertToCurrent()
	authVoter, err := voteState.GetAndUpdateAuthorizedVoter(clock.Epoch)
	if err != nil {
		return nil, err
	}

	err = verifySigner(authVoter, signers)
	if err != nil {
		return nil, err
	}

	return voteState, nil
}

func checkSlotsAreValid(voteState *VoteState, voteSlots []uint64, voteHash [32]byte, slotHashes SysvarSlotHashes) error {
	var err error
	i := uint64(0)
	j := uint64(len(slotHashes))

	for i < uint64(len(voteSlots)) && j > 0 {

		// "1) increment `i` to find the smallest slot `s` in `vote_slots`
		// where `s` >= `last_voted_slot`""
		lastVotedSlot, ok := voteState.LastVotedSlot()
		if ok && voteSlots[i] <= lastVotedSlot {
			i, err = safemath.CheckedAddU64(i, 1)
			if err != nil {
				panic("`i` is bounded by `MAX_LOCKOUT_HISTORY` when finding larger slots")
			}
			continue
		}

		// "2) Find the hash for this slot `s`.""
		k, err := safemath.CheckedSubU64(j, 1)
		if err != nil {
			panic("`j` is positive")
		}
		if voteSlots[i] != slotHashes[k].Slot {
			// Decrement `j` to find newer slots
			j, err = safemath.CheckedSubU64(j, 1)
			if err != nil {
				panic("`j` is positive when finding newer slots")
			}
			continue
		}

		// "3) Once the hash for `s` is found, bump `s` to the next slot
		// in `vote_slots` and continue."
		i, err = safemath.CheckedAddU64(i, 1)
		if err != nil {
			panic("`i` is bounded by `MAX_LOCKOUT_HISTORY` when hash is found")
		}
		j, err = safemath.CheckedSubU64(j, 1)
		if err != nil {
			panic("`j` is positive when hash is found")
		}
	}

	if j == uint64(len(slotHashes)) {
		klog.Errorf("%s dropped vote slots %#v, vote hash %s, slot hashes: %#v, too old ", voteState.NodePubkey, voteSlots, voteHash, slotHashes)
		return VoteErrVoteTooOld
	}

	if i != uint64(len(voteSlots)) {
		klog.Infof("%s dropped vote slots %#v failed to match slot hashes: %#v", voteState.NodePubkey, voteSlots, slotHashes)
		return VoteErrSlotsMismatch
	}

	if slotHashes[j].Hash != voteHash {
		klog.Warningf("%s dropped vote slots %#v failed to match hash %#v %#v", voteState.NodePubkey, voteSlots, voteHash, slotHashes[j].Hash)
		return VoteErrSlotHashMismatch
	}

	return nil
}

func processVoteUnfiltered(voteState *VoteState, voteSlots []uint64, vote *VoteInstrVote, slotHashes SysvarSlotHashes, epoch uint64, currentSlot uint64) error {
	err := checkSlotsAreValid(voteState, voteSlots, vote.Hash, slotHashes)
	if err != nil {
		return err
	}

	for _, voteSlot := range voteSlots {
		voteState.ProcessNextVoteSlot(voteSlot, epoch, currentSlot)
	}

	return nil
}

func processVote(voteState *VoteState, vote *VoteInstrVote, slotHashes SysvarSlotHashes, epoch uint64, currentSlot uint64) error {
	if len(vote.Slots) == 0 {
		return VoteErrEmptySlots
	}

	var earliestSlotInHistory uint64
	if len(slotHashes) != 0 {
		earliestSlotInHistory = slotHashes[len(slotHashes)-1].Slot
	}

	var voteSlots []uint64
	for _, slot := range vote.Slots {
		if slot >= earliestSlotInHistory {
			voteSlots = append(voteSlots, slot)
		}
	}

	if len(voteSlots) == 0 {
		return VoteErrVotesTooOldAllFiltered
	}

	return processVoteUnfiltered(voteState, voteSlots, vote, slotHashes, epoch, currentSlot)
}

func VoteProgramProcessVote(voteAcct *BorrowedAccount, slotHashes SysvarSlotHashes, clock SysvarClock, vote *VoteInstrVote, signers []solana.PublicKey, f features.Features) error {
	voteState, err := verifyAndGetVoteState(voteAcct, clock, signers)
	if err != nil {
		return err
	}

	err = processVote(voteState, vote, slotHashes, clock.Epoch, clock.Slot)
	if err != nil {
		return err
	}

	if vote.Timestamp != nil {
		if len(vote.Slots) == 0 {
			return VoteErrEmptySlots
		}
		maxSlot := vote.Slots[0]
		for _, slot := range vote.Slots {
			if slot > maxSlot {
				maxSlot = slot
			}
		}
		err = voteState.ProcessTimestamp(maxSlot, *vote.Timestamp)
		if err != nil {
			return err
		}
	}

	err = setVoteAccountState(voteAcct, voteState, f)

	return err
}
