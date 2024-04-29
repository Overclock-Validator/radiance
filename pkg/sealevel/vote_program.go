package sealevel

import (
	"math"

	"github.com/edwingeng/deque/v2"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/safemath"
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

type VoteLockout struct {
	Slot              uint64
	ConfirmationCount uint32
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

func (lockout *VoteLockout) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	lockout.Slot, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	lockout.ConfirmationCount, err = decoder.ReadUint32(bin.LE)
	return err
}

func (lockout *VoteLockout) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint64(lockout.Slot, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint32(lockout.ConfirmationCount, bin.LE)
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

	// TODO: implement instruction handling

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

	return nil
}
