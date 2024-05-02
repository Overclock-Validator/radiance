package sealevel

import (
	"bytes"
	"errors"
	"math"

	"github.com/edwingeng/deque/v2"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/tidwall/btree"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/safemath"
)

const (
	VoteStateVersionV0_23_5 = iota
	VoteStateVersionV1_14_11
	VoteStateVersionCurrent
)

const (
	VoteStateV2Size = 3731
	VoteStateV3Size = 3762
)

func sizeOfVersionedVoteState(f features.Features) uint64 {
	if f.IsActive(features.VoteStateAddVoteLatency) {
		return VoteStateV3Size
	} else {
		return VoteStateV2Size
	}
}

type PriorVoter struct {
	Pubkey     solana.PublicKey
	EpochStart uint64
	EpochEnd   uint64
	Slot       uint64
}

type PriorVoters0_23_5 struct {
	Buf   [32]PriorVoter
	Index uint64
}

type PriorVoters struct {
	Buf     [32]PriorVoter
	Index   uint64
	IsEmpty bool
}

type EpochCredits struct {
	Epoch       uint64
	Credits     uint64
	PrevCredits uint64
}

type BlockTimestamp struct {
	Slot      uint64
	Timestamp uint64
}

type AuthorizedVoter struct {
	Epoch  uint64
	Pubkey solana.PublicKey
}

type AuthorizedVoters struct {
	AuthorizedVoters btree.Map[uint64, solana.PublicKey]
}

type VoteLockout struct {
	Slot              uint64
	ConfirmationCount uint32
}

type LandedVote struct {
	Latency byte
	Lockout VoteLockout
}

type VoteState0_23_5 struct {
	NodePubkey           solana.PublicKey
	AuthorizedVoter      solana.PublicKey
	AuthorizedVoterEpoch uint64
	PriorVoters          PriorVoters0_23_5
	AuthorizedWithdrawer solana.PublicKey
	Commission           byte
	Votes                deque.Deque[VoteLockout]
	RootSlot             *uint64
	EpochCredits         []EpochCredits
	LastTimestamp        BlockTimestamp
}

type VoteState1_14_11 struct {
	NodePubkey           solana.PublicKey
	AuthorizedWithdrawer solana.PublicKey
	Commission           byte
	Votes                *deque.Deque[VoteLockout]
	RootSlot             *uint64
	AuthorizedVoters     AuthorizedVoters
	PriorVoters          PriorVoters
	EpochCredits         []EpochCredits
	LastTimestamp        BlockTimestamp
}

type VoteState struct {
	NodePubkey           solana.PublicKey
	AuthorizedWithdrawer solana.PublicKey
	Commission           byte
	Votes                *deque.Deque[LandedVote]
	RootSlot             *uint64
	AuthorizedVoters     AuthorizedVoters
	PriorVoters          PriorVoters
	EpochCredits         []EpochCredits
	LastTimestamp        BlockTimestamp
}

type VoteStateVersions struct {
	Type     uint32
	V0_23_5  VoteState0_23_5
	V1_14_11 VoteState1_14_11
	Current  VoteState
}

func (priorVoter *PriorVoter) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	pk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(priorVoter.Pubkey[:], pk)

	priorVoter.EpochStart, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	priorVoter.EpochEnd, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	priorVoter.Slot, err = decoder.ReadUint64(bin.LE)
	return err
}

func (priorVoter *PriorVoter) MarshalWithEncoder(encoder *bin.Encoder) error {
	err := encoder.WriteBytes(priorVoter.Pubkey[:], false)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(priorVoter.EpochStart, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(priorVoter.EpochEnd, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(priorVoter.Slot, bin.LE)
	if err != nil {
		return err
	}

	return nil
}

func (priorVoters *PriorVoters0_23_5) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	for count := 0; count < 32; count++ {
		var priorVoter PriorVoter
		err = priorVoter.UnmarshalWithDecoder(decoder)
		if err != nil {
			return err
		}
		priorVoters.Buf[count] = priorVoter
	}
	priorVoters.Index, err = decoder.ReadUint64(bin.LE)
	return err
}

func (priorVoters *PriorVoters0_23_5) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	for count := 0; count < 32; count++ {
		err = priorVoters.Buf[count].MarshalWithEncoder(encoder)
		if err != nil {
			return err
		}
	}

	err = encoder.WriteUint64(priorVoters.Index, bin.LE)
	if err != nil {
		return err
	}
	return nil
}

func (priorVoters *PriorVoters) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	for count := 0; count < 32; count++ {
		var priorVoter PriorVoter
		err = priorVoter.UnmarshalWithDecoder(decoder)
		if err != nil {
			return err
		}
		priorVoters.Buf[count] = priorVoter
	}
	priorVoters.Index, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	priorVoters.IsEmpty, err = decoder.ReadBool()
	return err
}

func (priorVoters *PriorVoters) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	for count := 0; count < 32; count++ {
		err = priorVoters.Buf[count].MarshalWithEncoder(encoder)
		if err != nil {
			return err
		}
	}

	err = encoder.WriteUint64(priorVoters.Index, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteBool(priorVoters.IsEmpty)
	if err != nil {
		return err
	}

	return nil
}

func (priorVoters *PriorVoters) Last() *PriorVoter {
	if !priorVoters.IsEmpty {
		return &priorVoters.Buf[priorVoters.Index]
	} else {
		return nil
	}
}

func (priorVoters *PriorVoters) Append(priorVoter PriorVoter) {
	priorVoters.Index++
	priorVoters.Buf[priorVoters.Index] = priorVoter
	priorVoters.IsEmpty = false
}

func (epochCredits *EpochCredits) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	epochCredits.Epoch, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	epochCredits.Credits, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	epochCredits.PrevCredits, err = decoder.ReadUint64(bin.LE)
	return err
}

func (epochCredits *EpochCredits) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint64(epochCredits.Epoch, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(epochCredits.Credits, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(epochCredits.PrevCredits, bin.LE)
	return err
}

func (landedVote *LandedVote) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	landedVote.Latency, err = decoder.ReadByte()
	if err != nil {
		return err
	}

	err = landedVote.Lockout.UnmarshalWithDecoder(decoder)
	return err
}

func (landedVote *LandedVote) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteByte(landedVote.Latency)
	if err != nil {
		return err
	}

	err = landedVote.Lockout.MarshalWithEncoder(encoder)
	return err
}

func (blockTimestamp *BlockTimestamp) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	blockTimestamp.Slot, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	blockTimestamp.Timestamp, err = decoder.ReadUint64(bin.LE)
	return err
}

func (blockTimestamp *BlockTimestamp) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint64(blockTimestamp.Slot, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(blockTimestamp.Timestamp, bin.LE)
	return err
}

func (voteState *VoteState0_23_5) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	nodePk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(voteState.NodePubkey[:], nodePk)

	authVoter, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(voteState.AuthorizedVoter[:], authVoter)

	voteState.AuthorizedVoterEpoch, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	err = voteState.PriorVoters.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}

	authWithdrawer, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(voteState.AuthorizedWithdrawer[:], authWithdrawer)

	voteState.Commission, err = decoder.ReadByte()
	if err != nil {
		return err
	}

	numLockouts, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	for count := uint64(0); count < numLockouts; count++ {
		var lockout VoteLockout
		err = lockout.UnmarshalWithDecoder(decoder)
		if err != nil {
			return err
		}
		voteState.Votes.PushBack(lockout)
	}

	hasRootSlot, err := decoder.ReadBool()
	if err != nil {
		return err
	}

	if hasRootSlot {
		rootSlot, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}
		voteState.RootSlot = &rootSlot
	}

	numEpochCredits, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	for count := uint64(0); count < numEpochCredits; count++ {
		var epochCredits EpochCredits
		err = epochCredits.UnmarshalWithDecoder(decoder)
		if err != nil {
			return err
		}
		voteState.EpochCredits = append(voteState.EpochCredits, epochCredits)
	}

	err = voteState.LastTimestamp.UnmarshalWithDecoder(decoder)
	return err
}

func (voteState *VoteState0_23_5) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteBytes(voteState.NodePubkey[:], false)
	if err != nil {
		return err
	}

	err = encoder.WriteBytes(voteState.AuthorizedVoter[:], false)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(voteState.AuthorizedVoterEpoch, bin.LE)
	if err != nil {
		return err
	}

	err = voteState.PriorVoters.MarshalWithEncoder(encoder)
	if err != nil {
		return err
	}

	err = encoder.WriteBytes(voteState.AuthorizedWithdrawer[:], false)
	if err != nil {
		return err
	}

	err = encoder.WriteByte(voteState.Commission)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(uint64(voteState.Votes.Len()), bin.LE)
	if err != nil {
		return err
	}
	voteState.Votes.Range(func(i int, lockout VoteLockout) bool {
		err = lockout.MarshalWithEncoder(encoder)
		if err != nil {
			return false
		} else {
			return true
		}
	})

	if err != nil {
		return err
	}

	if voteState.RootSlot != nil {
		err = encoder.WriteUint64(*voteState.RootSlot, bin.LE)
		if err != nil {
			return err
		}
	}

	err = encoder.WriteUint64(uint64(len(voteState.EpochCredits)), bin.LE)
	if err != nil {
		return err
	}
	for _, epochCredit := range voteState.EpochCredits {
		err = epochCredit.MarshalWithEncoder(encoder)
		if err != nil {
			return err
		}
	}

	err = voteState.LastTimestamp.MarshalWithEncoder(encoder)
	return err
}

func (authVoter *AuthorizedVoter) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	authVoter.Epoch, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	pk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(authVoter.Pubkey[:], pk)
	return nil
}

func (authVoter *AuthorizedVoter) MarshalWithEncoder(encoder *bin.Encoder) error {
	err := encoder.WriteUint64(authVoter.Epoch, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteBytes(authVoter.Pubkey[:], false)
	return err
}

func (authVoters *AuthorizedVoters) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	numAuthVoters, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	for count := uint64(0); count < numAuthVoters; count++ {
		var authVoter AuthorizedVoter
		err = authVoter.UnmarshalWithDecoder(decoder)
		if err != nil {
			return err
		}
		authVoters.AuthorizedVoters.Set(authVoter.Epoch, authVoter.Pubkey)
	}
	return nil
}

func (authVoters *AuthorizedVoters) MarshalWithEncoder(encoder *bin.Encoder) error {
	err := encoder.WriteUint64(uint64(authVoters.AuthorizedVoters.Len()), bin.LE)
	if err != nil {
		return err
	}
	for iter := authVoters.AuthorizedVoters.Iter(); iter.Next(); {
		authVoter := AuthorizedVoter{Epoch: iter.Key(), Pubkey: iter.Value()}
		err = authVoter.MarshalWithEncoder(encoder)
		if err != nil {
			return err
		}
	}
	return nil
}

func (authVoters *AuthorizedVoters) GetOrCalculateAuthorizedVoterForEpoch(epoch uint64) (solana.PublicKey, bool, error) {
	res, exists := authVoters.AuthorizedVoters.Get(epoch)
	if exists {
		return res, true, nil
	} else {
		var prevPk solana.PublicKey
		authVoters.AuthorizedVoters.Ascend(0, func(key uint64, value solana.PublicKey) bool {
			if key == epoch {
				return false
			} else {
				prevPk = value
				return true
			}
		})
		if prevPk.IsZero() {
			return prevPk, false, errors.New("Tried to query for the authorized voter of an epoch earlier than the current epoch. Earlier epochs have been purged")
		} else {
			return prevPk, false, nil
		}
	}
}

func (authVoters *AuthorizedVoters) GetAndCacheAuthorizedVoterForEpoch(epoch uint64) (solana.PublicKey, error) {
	voter, existed, err := authVoters.GetOrCalculateAuthorizedVoterForEpoch(epoch)
	if err != nil {
		return voter, err
	}

	if !existed {
		authVoters.AuthorizedVoters.Set(epoch, voter)
	}
	return voter, nil
}

func (authVoters *AuthorizedVoters) PurgeAuthorizedVoters(currentEpoch uint64) bool {
	var expiredKeys []uint64
	authVoters.AuthorizedVoters.Ascend(0, func(key uint64, value solana.PublicKey) bool {
		if key == currentEpoch {
			return false
		} else {
			expiredKeys = append(expiredKeys, key)
			return true
		}
	})

	for _, key := range expiredKeys {
		authVoters.AuthorizedVoters.Delete(key)
	}

	if authVoters.AuthorizedVoters.Len() == 0 {
		panic("invariant - AuthorizedVoters should not be empty")
	}
	return true
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

const InitialLockout = 2

func (lockout *VoteLockout) Lockout() uint64 {
	return uint64(math.Pow(InitialLockout, float64(lockout.ConfirmationCount)))
}

func (lockout *VoteLockout) LastLockedOutSlot() uint64 {
	return safemath.SaturatingAddU64(lockout.Slot, lockout.Lockout())
}

func (lockout *VoteLockout) IsLockedOutAtSlot(slot uint64) bool {
	return lockout.LastLockedOutSlot() >= slot
}

func (lockout *VoteLockout) IncreaseConfirmationCount(by uint32) {
	lockout.ConfirmationCount = safemath.SaturatingAddU32(lockout.ConfirmationCount, by)
}

func (voteState *VoteState1_14_11) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	nodePk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(voteState.NodePubkey[:], nodePk)

	authWithdrawer, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(voteState.AuthorizedWithdrawer[:], authWithdrawer)

	voteState.Commission, err = decoder.ReadByte()
	if err != nil {
		return err
	}

	numLockouts, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	for count := uint64(0); count < numLockouts; count++ {
		var lockout VoteLockout
		err = lockout.UnmarshalWithDecoder(decoder)
		if err != nil {
			return err
		}
		voteState.Votes.PushBack(lockout)
	}

	hasRootSlot, err := decoder.ReadBool()
	if err != nil {
		return err
	}

	if hasRootSlot {
		rootSlot, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}
		voteState.RootSlot = &rootSlot
	}

	err = voteState.AuthorizedVoters.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}

	err = voteState.PriorVoters.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}

	numEpochCredits, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	for count := uint64(0); count < numEpochCredits; count++ {
		var epochCredits EpochCredits
		err = epochCredits.UnmarshalWithDecoder(decoder)
		if err != nil {
			return err
		}
		voteState.EpochCredits = append(voteState.EpochCredits, epochCredits)
	}

	err = voteState.LastTimestamp.UnmarshalWithDecoder(decoder)
	return err
}

func (voteState *VoteState1_14_11) MarshalWithEncoder(encoder *bin.Encoder) error {
	err := encoder.WriteBytes(voteState.NodePubkey[:], false)
	if err != nil {
		return err
	}

	err = encoder.WriteBytes(voteState.AuthorizedWithdrawer[:], false)
	if err != nil {
		return err
	}

	err = encoder.WriteByte(voteState.Commission)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(uint64(voteState.Votes.Len()), bin.LE)
	if err != nil {
		return err
	}

	voteState.Votes.Range(func(i int, lockout VoteLockout) bool {
		err = lockout.MarshalWithEncoder(encoder)
		if err != nil {
			return false
		} else {
			return true
		}
	})

	if voteState.RootSlot != nil {
		err = encoder.WriteUint64(*voteState.RootSlot, bin.LE)
		if err != nil {
			return err
		}
	}

	err = voteState.AuthorizedVoters.MarshalWithEncoder(encoder)
	if err != nil {
		return err
	}

	err = voteState.PriorVoters.MarshalWithEncoder(encoder)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(uint64(len(voteState.EpochCredits)), bin.LE)
	if err != nil {
		return err
	}

	for _, epochCredits := range voteState.EpochCredits {
		err = epochCredits.MarshalWithEncoder(encoder)
		if err != nil {
			return err
		}
	}

	err = voteState.LastTimestamp.MarshalWithEncoder(encoder)
	return err
}

func (voteState *VoteState) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	nodePk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(voteState.NodePubkey[:], nodePk)

	authWithdrawer, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(voteState.AuthorizedWithdrawer[:], authWithdrawer)

	voteState.Commission, err = decoder.ReadByte()
	if err != nil {
		return err
	}

	numLockouts, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	for count := uint64(0); count < numLockouts; count++ {
		var landedVote LandedVote
		err = landedVote.UnmarshalWithDecoder(decoder)
		if err != nil {
			return err
		}
		voteState.Votes.PushBack(landedVote)
	}

	hasRootSlot, err := decoder.ReadBool()
	if err != nil {
		return err
	}

	if hasRootSlot {
		rootSlot, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}
		voteState.RootSlot = &rootSlot
	}

	err = voteState.AuthorizedVoters.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}

	err = voteState.PriorVoters.UnmarshalWithDecoder(decoder)
	if err != nil {
		return err
	}

	numEpochCredits, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	for count := uint64(0); count < numEpochCredits; count++ {
		var epochCredits EpochCredits
		err = epochCredits.UnmarshalWithDecoder(decoder)
		if err != nil {
			return err
		}
		voteState.EpochCredits = append(voteState.EpochCredits, epochCredits)
	}

	err = voteState.LastTimestamp.UnmarshalWithDecoder(decoder)
	return err
}

func (voteState *VoteState) MarshalWithEncoder(encoder *bin.Encoder) error {
	err := encoder.WriteBytes(voteState.NodePubkey[:], false)
	if err != nil {
		return err
	}

	err = encoder.WriteBytes(voteState.AuthorizedWithdrawer[:], false)
	if err != nil {
		return err
	}

	err = encoder.WriteByte(voteState.Commission)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(uint64(voteState.Votes.Len()), bin.LE)
	if err != nil {
		return err
	}

	voteState.Votes.Range(func(i int, landedVote LandedVote) bool {
		err = landedVote.MarshalWithEncoder(encoder)
		if err != nil {
			return false
		} else {
			return true
		}
	})

	if voteState.RootSlot != nil {
		err = encoder.WriteUint64(*voteState.RootSlot, bin.LE)
		if err != nil {
			return err
		}
	}

	err = voteState.AuthorizedVoters.MarshalWithEncoder(encoder)
	if err != nil {
		return err
	}

	err = voteState.PriorVoters.MarshalWithEncoder(encoder)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(uint64(len(voteState.EpochCredits)), bin.LE)
	if err != nil {
		return err
	}

	for _, epochCredits := range voteState.EpochCredits {
		err = epochCredits.MarshalWithEncoder(encoder)
		if err != nil {
			return err
		}
	}

	err = voteState.LastTimestamp.MarshalWithEncoder(encoder)
	return err
}

func (voteState *VoteState) GetAndUpdateAuthorizedVoter(currentEpoch uint64) (solana.PublicKey, error) {
	pubkey, err := voteState.AuthorizedVoters.GetAndCacheAuthorizedVoterForEpoch(currentEpoch)
	if err != nil {
		return pubkey, InstrErrInvalidAccountData
	}

	voteState.AuthorizedVoters.PurgeAuthorizedVoters(currentEpoch)
	return pubkey, nil
}

func (voteState *VoteState) SetNewAuthorizedVoter(authorized solana.PublicKey, currentEpoch uint64, targetEpoch uint64, verify func(epochAuthorizedVoter solana.PublicKey) error) error {
	epochAuthorizedVoter, err := voteState.GetAndUpdateAuthorizedVoter(currentEpoch)
	if err != nil {
		return err
	}

	err = verify(epochAuthorizedVoter)
	if err != nil {
		return err
	}

	_, exists := voteState.AuthorizedVoters.AuthorizedVoters.Get(currentEpoch)
	if exists {
		return VoteErrTooSoonToReauthorize
	}

	iter := voteState.AuthorizedVoters.AuthorizedVoters.Iter()
	exists = iter.Last()
	if !exists {
		return InstrErrInvalidAccountData
	}

	latestEpoch := iter.Key()
	latestAuthPubkey := iter.Value()

	if latestAuthPubkey != authorized {
		var epochOfLastAuthorizedSwitch uint64
		last := voteState.PriorVoters.Last()
		if last != nil {
			epochOfLastAuthorizedSwitch = last.EpochEnd
		}

		if targetEpoch <= latestEpoch {
			panic("invariant targetEpoch > latestEpoch must hold")
		}

		voteState.PriorVoters.Append(PriorVoter{Pubkey: latestAuthPubkey, EpochStart: epochOfLastAuthorizedSwitch, EpochEnd: targetEpoch})
	}

	voteState.AuthorizedVoters.AuthorizedVoters.Set(targetEpoch, authorized)
	return nil
}

func (voteState *VoteState) LastLockout() *VoteLockout {
	landedVote, ok := voteState.Votes.Back()
	if !ok {
		return nil
	}
	return &landedVote.Lockout
}

func (voteState *VoteState) LastVotedSlot() (uint64, bool) {
	lastLockout := voteState.LastLockout()
	if lastLockout == nil {
		return 0, false
	} else {
		return lastLockout.Slot, true
	}
}

func (voteState *VoteState) PopExpiredVotes(nextVoteSlot uint64) {
	var vote *VoteLockout
	for {
		vote = voteState.LastLockout()
		if vote == nil {
			break
		}
		if !vote.IsLockedOutAtSlot(nextVoteSlot) {
			voteState.Votes.PopBack()
		} else {
			break
		}
	}
}

func (voteState *VoteState) DoubleLockouts() {
	var indicesToIncreaseConfirmationCount []int
	stackDepth := uint64(voteState.Votes.Len())
	voteState.Votes.Range(func(idx int, landedVote LandedVote) bool {
		j, err := safemath.CheckedAddU64(uint64(idx), uint64(landedVote.Lockout.ConfirmationCount))
		if err != nil {
			panic("`confirmation_count` and tower_size should be bounded by `MAX_LOCKOUT_HISTORY`")
		}
		if stackDepth > j {
			indicesToIncreaseConfirmationCount = append(indicesToIncreaseConfirmationCount, idx)
		}
		return true
	})

	for _, idx := range indicesToIncreaseConfirmationCount {
		landedVote := voteState.Votes.Peek(idx)
		landedVote.Lockout.IncreaseConfirmationCount(1)
		voteState.Votes.Replace(idx, landedVote)
	}
}

func (voteState *VoteState) ComputeVoteLatency(votedForSlot uint64, currentSlot uint64) byte {
	return byte(math.Min(float64(safemath.SaturatingSubU64(currentSlot, votedForSlot)), math.MaxUint8))
}

const (
	MaxLockoutHistory         = 31
	VoteCreditsGraceSlots     = 2
	VoteCreditsMaximumPerSlot = 8
	MaxEpochCreditsHistory    = 64
)

func (voteState *VoteState) CreditsForVoteAtIndex(index uint64) uint64 {
	landedVote := voteState.Votes.Peek(int(index))
	latency := landedVote.Latency

	if latency == 0 {
		return 1
	} else {
		diff, err := safemath.CheckedSubU8(latency, VoteCreditsGraceSlots)
		if err != nil || diff == 0 {
			return VoteCreditsMaximumPerSlot
		} else {
			credits, err := safemath.CheckedSubU8(VoteCreditsMaximumPerSlot, diff)
			if err != nil || credits == 0 {
				return 1
			} else {
				return uint64(credits)
			}
		}
	}
}

/*
	pub fn increment_credits(&mut self, epoch: Epoch, credits: u64) {
	    // increment credits, record by epoch

	    // never seen a credit
	    if self.epoch_credits.is_empty() {
	        self.epoch_credits.push((epoch, 0, 0));
	    } else if epoch != self.epoch_credits.last().unwrap().0 {
	        let (_, credits, prev_credits) = *self.epoch_credits.last().unwrap();

	        if credits != prev_credits {
	            // if credits were earned previous epoch
	            // append entry at end of list for the new epoch
	            self.epoch_credits.push((epoch, credits, credits));
	        } else {
	            // else just move the current epoch
	            self.epoch_credits.last_mut().unwrap().0 = epoch;
	        }

	        // Remove too old epoch_credits
	        if self.epoch_credits.len() > MAX_EPOCH_CREDITS_HISTORY {
	            self.epoch_credits.remove(0);
	        }
	    }

	    self.epoch_credits.last_mut().unwrap().1 =
	        self.epoch_credits.last().unwrap().1.saturating_add(credits);
	}
*/
func (voteState *VoteState) IncrementCredits(epoch uint64, credits uint64) {
	if len(voteState.EpochCredits) == 0 {
		voteState.EpochCredits = append(voteState.EpochCredits, EpochCredits{Epoch: 0, Credits: 0, PrevCredits: 0})
	} else if epoch != voteState.EpochCredits[len(voteState.EpochCredits)-1].Epoch {
		ec := voteState.EpochCredits[len(voteState.EpochCredits)-1]
		if ec.Credits != ec.PrevCredits {
			voteState.EpochCredits = append(voteState.EpochCredits, EpochCredits{Epoch: epoch, Credits: ec.Credits, PrevCredits: ec.Credits})
		} else {
			voteState.EpochCredits[len(voteState.EpochCredits)-1].Epoch = epoch
		}

		if len(voteState.EpochCredits) > MaxEpochCreditsHistory {
			voteState.EpochCredits = voteState.EpochCredits[1:]
		}
	}

	currentCredits := voteState.EpochCredits[len(voteState.EpochCredits)-1].Credits
	voteState.EpochCredits[len(voteState.EpochCredits)-1].Credits = safemath.SaturatingAddU64(currentCredits, credits)
}

func (voteState *VoteState) ProcessNextVoteSlot(nextVoteSlot uint64, epoch uint64, currentSlot uint64) {
	lastVotedSlot, ok := voteState.LastVotedSlot()
	if ok && nextVoteSlot <= lastVotedSlot {
		return
	}

	voteState.PopExpiredVotes(nextVoteSlot)

	landedVote := LandedVote{Latency: voteState.ComputeVoteLatency(nextVoteSlot, currentSlot),
		Lockout: VoteLockout{Slot: nextVoteSlot, ConfirmationCount: 1}}

	if voteState.Votes.Len() == MaxLockoutHistory {
		credits := voteState.CreditsForVoteAtIndex(0)
		landedVote := voteState.Votes.PopFront()
		voteState.RootSlot = &landedVote.Lockout.Slot

		voteState.IncrementCredits(epoch, credits)
	}

	voteState.Votes.PushBack(landedVote)
	voteState.DoubleLockouts()
}

func (voteState *VoteState) ProcessTimestamp(slot uint64, timestamp uint64) error {
	if (slot < voteState.LastTimestamp.Slot || timestamp < voteState.LastTimestamp.Timestamp) ||
		(slot == voteState.LastTimestamp.Slot && BlockTimestamp{Slot: slot, Timestamp: timestamp} != voteState.LastTimestamp &&
			voteState.LastTimestamp.Slot != 0) {
		return VoteErrTimestampTooOld
	}

	voteState.LastTimestamp = BlockTimestamp{Slot: slot, Timestamp: timestamp}
	return nil
}

func (voteStateVersions *VoteStateVersions) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	voteStateVersions.Type, err = decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
	}

	switch voteStateVersions.Type {
	case VoteStateVersionV0_23_5:
		{
			err = voteStateVersions.V0_23_5.UnmarshalWithDecoder(decoder)
		}
	case VoteStateVersionV1_14_11:
		{
			err = voteStateVersions.V1_14_11.UnmarshalWithDecoder(decoder)
		}
	case VoteStateVersionCurrent:
		{
			err = voteStateVersions.Current.UnmarshalWithDecoder(decoder)
		}
	default:
		{
			err = InstrErrInvalidAccountData
		}
	}
	return err
}

func (voteStateVersions *VoteStateVersions) MarshalWithEncoder(encoder *bin.Encoder) error {
	err := encoder.WriteUint32(voteStateVersions.Type, bin.LE)
	if err != nil {
		return err
	}

	switch voteStateVersions.Type {
	case VoteStateVersionV0_23_5:
		{
			err = voteStateVersions.V0_23_5.MarshalWithEncoder(encoder)
		}
	case VoteStateVersionV1_14_11:
		{
			err = voteStateVersions.V1_14_11.MarshalWithEncoder(encoder)
		}
	case VoteStateVersionCurrent:
		{
			err = voteStateVersions.Current.MarshalWithEncoder(encoder)
		}
	}

	return err
}

func (voteStateVersions *VoteStateVersions) IsInitialized() bool {
	switch voteStateVersions.Type {
	case VoteStateVersionV0_23_5:
		{
			return voteStateVersions.V0_23_5.AuthorizedVoter != solana.PublicKey{}
		}
	case VoteStateVersionV1_14_11:
		{
			return voteStateVersions.V1_14_11.AuthorizedVoters.AuthorizedVoters.Len() != 0
		}
	case VoteStateVersionCurrent:
		{
			return voteStateVersions.Current.AuthorizedVoters.AuthorizedVoters.Len() != 0
		}
	default:
		{
			panic("VoteStateVersions in invalid state - programming error")
		}
	}
}

func (voteStateVersions *VoteStateVersions) ConvertToCurrent() *VoteState {
	switch voteStateVersions.Type {
	case VoteStateVersionV0_23_5:
		{
			state := &voteStateVersions.V0_23_5

			var authVoters AuthorizedVoters
			authVoters.AuthorizedVoters.Set(state.AuthorizedVoterEpoch, state.AuthorizedVoter)

			newVoteState := &VoteState{NodePubkey: state.NodePubkey,
				AuthorizedWithdrawer: state.AuthorizedWithdrawer,
				Commission:           state.Commission,
				RootSlot:             state.RootSlot,
				AuthorizedVoters:     authVoters,
				EpochCredits:         state.EpochCredits,
				LastTimestamp:        state.LastTimestamp,
			}

			state.Votes.Range(func(i int, lockout VoteLockout) bool {
				newVoteState.Votes.PushBack(LandedVote{Latency: 0, Lockout: lockout})
				return true
			})

			return newVoteState
		}

	case VoteStateVersionV1_14_11:
		{
			state := &voteStateVersions.V1_14_11

			newVoteState := &VoteState{NodePubkey: state.NodePubkey,
				AuthorizedWithdrawer: state.AuthorizedWithdrawer,
				Commission:           state.Commission,
				RootSlot:             state.RootSlot,
				AuthorizedVoters:     state.AuthorizedVoters,
				PriorVoters:          state.PriorVoters,
				EpochCredits:         state.EpochCredits,
				LastTimestamp:        state.LastTimestamp}

			state.Votes.Range(func(i int, lockout VoteLockout) bool {
				newVoteState.Votes.PushBack(LandedVote{Latency: 0, Lockout: lockout})
				return true
			})

			return newVoteState
		}

	case VoteStateVersionCurrent:
		{
			return &voteStateVersions.Current
		}

	default:
		{
			panic("vote account in invalid state - potential programming error")
		}
	}
}

func unmarshalVersionedVoteState(data []byte) (*VoteStateVersions, error) {
	versioned := new(VoteStateVersions)
	decoder := bin.NewBinDecoder(data)

	err := versioned.UnmarshalWithDecoder(decoder)
	if err != nil {
		return nil, InstrErrInvalidAccountData
	} else {
		return versioned, nil
	}
}

func marshalVersionedVoteState(voteStateVersions *VoteStateVersions) ([]byte, error) {
	buffer := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(buffer)

	err := voteStateVersions.MarshalWithEncoder(encoder)
	if err != nil {
		return nil, err
	} else {
		return buffer.Bytes(), nil
	}
}

func newVoteState1_14_11FromCurrent(voteState *VoteState) *VoteState1_14_11 {
	newVoteState := new(VoteState1_14_11)
	newVoteState.NodePubkey = voteState.NodePubkey
	newVoteState.AuthorizedWithdrawer = voteState.AuthorizedWithdrawer
	newVoteState.Commission = voteState.Commission
	newVoteState.RootSlot = voteState.RootSlot
	newVoteState.AuthorizedVoters = voteState.AuthorizedVoters
	newVoteState.PriorVoters = voteState.PriorVoters
	newVoteState.EpochCredits = voteState.EpochCredits
	newVoteState.LastTimestamp = voteState.LastTimestamp

	voteState.Votes.Range(func(i int, landedVote LandedVote) bool {
		newVoteState.Votes.PushBack(landedVote.Lockout)
		return true
	})

	return newVoteState
}

func newVoteStateFromVoteInit(voteInit VoteInstrVoteInit, clock SysvarClock) *VoteState {
	voteState := new(VoteState)
	voteState.NodePubkey = voteInit.NodePubkey

	var authVoters AuthorizedVoters
	authVoters.AuthorizedVoters.Set(clock.Epoch, voteInit.AuthorizedVoter)
	voteState.AuthorizedVoters = authVoters

	voteState.AuthorizedWithdrawer = voteInit.AuthorizedWithdrawer
	voteState.Commission = voteInit.Commission
	return voteState
}

func setVoteAccountState(acct *BorrowedAccount, voteState *VoteState, f features.Features) error {
	// "Only if vote_state_add_vote_latency feature is enabled should the new version of vote state be stored"
	if f.IsActive(features.VoteStateAddVoteLatency) {
		// "If the account is not large enough to store the vote state, then attempt a realloc to make it large enough.
		// The realloc can only proceed if the vote account has balance sufficient for rent exemption at the new size."
		if len(acct.Data()) < VoteStateV3Size &&
			(!acct.IsRentExemptAtDataLength(VoteStateV3Size) || acct.SetDataLength(VoteStateV3Size, f) != nil) {
			// "Account cannot be resized to the size of a vote state as it will not be rent exempt, or failed to be
			// resized for other reasons.  So store the V1_14_11 version."
			newVoteState := newVoteState1_14_11FromCurrent(voteState)
			newVoteStateVersioned := new(VoteStateVersions)
			newVoteStateVersioned.V1_14_11 = *newVoteState
			voteStateBytes, err := marshalVersionedVoteState(newVoteStateVersioned)
			if err != nil {
				return err
			}
			err = acct.SetState(f, voteStateBytes)
			return err
		} else {
			// "Vote account is large enough to store the newest version of vote state"
			newVoteStateVersioned := new(VoteStateVersions)
			newVoteStateVersioned.Current = *voteState
			voteStateBytes, err := marshalVersionedVoteState(newVoteStateVersioned)
			if err != nil {
				return err
			}
			err = acct.SetState(f, voteStateBytes)
			return err
		}
	} else {
		// "Else when the vote_state_add_vote_latency feature is not enabled, then the V1_14_11 version is stored"
		newVoteState := newVoteState1_14_11FromCurrent(voteState)
		newVoteStateVersioned := new(VoteStateVersions)
		newVoteStateVersioned.V1_14_11 = *newVoteState
		voteStateBytes, err := marshalVersionedVoteState(newVoteStateVersioned)
		if err != nil {
			return err
		}
		err = acct.SetState(f, voteStateBytes)
		return err
	}
}
