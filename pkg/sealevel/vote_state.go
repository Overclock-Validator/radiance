package sealevel

import (
	"bytes"

	"github.com/edwingeng/deque/v2"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/tidwall/btree"
	"go.firedancer.io/radiance/pkg/features"
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
	AuthorizedVoters btree.BTreeG[AuthorizedVoter]
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
	Votes                deque.Deque[VoteLockout]
	RootSlot             *uint64
	AuthorizedVoters     AuthorizedVoters
	PriorVoters          PriorVoters
	EpochCredits         []EpochCredits
	LastTimestamp        BlockTimestamp
}

type VoteStateCurrent struct {
	NodePubkey           solana.PublicKey
	AuthorizedWithdrawer solana.PublicKey
	Commission           byte
	Votes                deque.Deque[LandedVote]
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
	Current  VoteStateCurrent
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
		authVoters.AuthorizedVoters.Set(authVoter)
	}
	return nil
}

func (authVoters *AuthorizedVoters) MarshalWithEncoder(encoder *bin.Encoder) error {
	err := encoder.WriteUint64(uint64(authVoters.AuthorizedVoters.Len()), bin.LE)
	if err != nil {
		return err
	}
	for iter := authVoters.AuthorizedVoters.Iter(); iter.Next(); {
		authVoter := iter.Item()
		err = authVoter.MarshalWithEncoder(encoder)
		if err != nil {
			return err
		}
	}
	return nil
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

func (voteState *VoteStateCurrent) UnmarshalWithDecoder(decoder *bin.Decoder) error {
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

func (voteState *VoteStateCurrent) MarshalWithEncoder(encoder *bin.Encoder) error {
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
