package rent

import (
	"crypto/sha256"
	"fmt"
	"math"

	"github.com/Overclock-Validator/mithril/pkg/accounts"
	"github.com/Overclock-Validator/mithril/pkg/features"
	"github.com/Overclock-Validator/mithril/pkg/sealevel"
	"github.com/Overclock-Validator/mithril/pkg/util"
	"github.com/gagliardetto/solana-go"
)

const (
	RentStateUninitialized = iota
	RentStateRentPaying
	RentStateRentExempt
)

type RentPayingInfo struct {
	Lamports uint64
	DataSize uint64
}

type RentStateInfo struct {
	RentState      uint64
	RentPayingInfo RentPayingInfo
}

func rentStateFromAcct(acct *accounts.Account, rent *sealevel.SysvarRent) *RentStateInfo {
	if acct.Lamports == 0 {
		return &RentStateInfo{RentState: RentStateUninitialized}
	} else if rent.IsExempt(acct.Lamports, uint64(len(acct.Data))) {
		return &RentStateInfo{RentState: RentStateRentExempt}
	} else {
		return &RentStateInfo{RentState: RentStateRentPaying, RentPayingInfo: RentPayingInfo{Lamports: acct.Lamports, DataSize: uint64(len(acct.Data))}}
	}
}

func NewRentStateInfo(rent *sealevel.SysvarRent, txCtx *sealevel.TransactionCtx, tx *solana.Transaction) []*RentStateInfo {
	rentStateInfos := make([]*RentStateInfo, 0)

	for idx, pk := range tx.Message.AccountKeys {
		isWritable, _ := tx.Message.IsWritable(pk)
		if isWritable {
			acct, err := txCtx.AccountAtIndex(uint64(idx))
			if err != nil {
				panic("error getting acct")
			}

			rentStateInfo := rentStateFromAcct(acct, rent)
			rentStateInfos = append(rentStateInfos, rentStateInfo)
		} else {
			rentStateInfos = append(rentStateInfos, nil)
		}
	}

	return rentStateInfos
}

func checkRentStateTransitionAllowed(preRentState *RentStateInfo, postRentState *RentStateInfo, txCtx *sealevel.TransactionCtx, idx uint64) error {
	if preRentState == nil && postRentState == nil {
		return nil
	} else if preRentState == nil && postRentState != nil {
		panic("programming error - shouldn't be possible")
	} else if preRentState != nil && postRentState == nil {
		panic("programming error - shouldn't be possible")
	}

	acct, err := txCtx.AccountAtIndex(idx)
	if err != nil {
		panic("programming error - acct didn't exist in TransactionAccounts")
	}

	if acct.Key != sealevel.IncineratorAddr {
		if postRentState.RentState == RentStateUninitialized {
			return nil
		} else if postRentState.RentState == RentStateRentExempt {
			return nil
		} else if postRentState.RentState == RentStateRentPaying {
			if preRentState.RentState == RentStateUninitialized {
				return fmt.Errorf("rent state transition not allowed")
			} else if preRentState.RentState == RentStateRentExempt {
				return fmt.Errorf("rent state transition not allowed")
			} else if preRentState.RentState == RentStateRentPaying {
				if postRentState.RentPayingInfo.DataSize == preRentState.RentPayingInfo.DataSize && postRentState.RentPayingInfo.Lamports <= preRentState.RentPayingInfo.Lamports {
					return nil
				} else {
					return fmt.Errorf("rent state transition not allowed")
				}
			}
		}
	}

	return nil
}

func VerifyRentStateChanges(preStates []*RentStateInfo, postStates []*RentStateInfo, txCtx *sealevel.TransactionCtx) error {
	if len(preStates) != len(postStates) {
		panic("programming error - pre tx states and post tx states must be same length")
	}

	for count := uint64(0); count < uint64(len(preStates)); count++ {
		err := checkRentStateTransitionAllowed(preStates[count], postStates[count], txCtx, count)
		if err != nil {
			return err
		}
	}

	return nil
}

func MaybeSetRentExemptRentEpochMax(slotCtx *sealevel.SlotCtx, rent *sealevel.SysvarRent, f *features.Features, txAccts *sealevel.TransactionAccounts) {
	for idx := range txAccts.Accounts {
		if ShouldSetRentExemptRentEpochMax(slotCtx, rent, f, txAccts.Accounts[idx]) {
			txAccts.Accounts[idx].RentEpoch = math.MaxUint64
			txAccts.Touch(uint64(idx))
		}
	}
}

func ShouldSetRentExemptRentEpochMax(slotCtx *sealevel.SlotCtx, rent *sealevel.SysvarRent, f *features.Features, acct *accounts.Account) bool {
	if f.IsActive(features.DisableRentFeesCollection) {
		if acct.RentEpoch != math.MaxUint64 && acct.Lamports >= rent.MinimumBalance(uint64(len(acct.Data))) {
			return true
		}
		return false
	}

	if acct.RentEpoch == math.MaxUint64 || acct.RentEpoch > slotCtx.Epoch {
		return false
	}

	if acct.IsExecutable() || acct.Key == sealevel.IncineratorAddr {
		return true
	}

	if acct.Lamports != 0 && acct.Lamports < rent.MinimumBalance(uint64(len(acct.Data))) {
		return false
	}

	return true
}

const (
	RentExempt = iota
	RentNoCollectionNow
	RentCollectRent
)

func calculateRentResult(slotCtx *sealevel.SlotCtx, rent *sealevel.SysvarRent, acct *accounts.Account) int {
	if acct.RentEpoch == math.MaxUint64 || acct.RentEpoch > slotCtx.Epoch {
		return RentNoCollectionNow
	}

	if acct.Executable || acct.Key == sealevel.IncineratorAddr {
		return RentExempt
	}

	if acct.Lamports >= rent.MinimumBalance(uint64(len(acct.Data))) {
		return RentExempt
	}

	// TODO: implement collection logic (testnet/devnet still have rent paying accounts)
	return RentExempt
}

// TODO: implement actual rent collection logic for networks other than mainnet-beta, since clusters like testnet and
// devnet still have rent paying accounts.
func collectRentFromAcct(slotCtx *sealevel.SlotCtx, rent *sealevel.SysvarRent, acct *accounts.Account) (*accounts.Account, bool) {

	if !slotCtx.Features.IsActive(features.DisableRentFeesCollection) {
		result := calculateRentResult(slotCtx, rent, acct)

		if result == RentExempt {
			acct.RentEpoch = math.MaxUint64
			return acct, true
		} else if result == RentNoCollectionNow {
			return acct, false
		} else /*result == RentCollectRent*/ {
			panic("mainnet-beta shouldn't have any rent paying accounts")
		}
	} else {
		if acct.RentEpoch != math.MaxUint64 && acct.Lamports >= rent.MinimumBalance(uint64(len(acct.Data))) {
			acct.RentEpoch = math.MaxUint64
			return acct, true
		} else {
			return acct, false
		}
	}
}

func collectRent(slotCtx *sealevel.SlotCtx, rent *sealevel.SysvarRent, pubkey solana.PublicKey) (*accounts.Account, bool) {
	acct, err := slotCtx.GetAccount(pubkey)
	if err != nil {
		acct, err = slotCtx.AccountsDb.GetAccount(pubkey)
		if err != nil {
			panic("unable to find account for rent collection")
		}
	}

	if acct.Lamports == 0 {
		return nil, false
	}

	h := sha256.New()
	h.Write(acct.Data)
	fmt.Printf("collectRent acct: pubkey %s, lamports %d, owner %s, rent_epoch %d, data hash: %s\n", acct.Key, acct.Lamports, solana.PublicKeyFromBytes(acct.Owner[:]), acct.RentEpoch, solana.HashFromBytes(h.Sum(nil)))

	return collectRentFromAcct(slotCtx, rent, acct)
}

func CollectRentEagerly(slotCtx *sealevel.SlotCtx, rent *sealevel.SysvarRent, epochSchedule *sealevel.SysvarEpochSchedule) []*accounts.Account {
	fmt.Printf("CollectRentEagerly ParentSlot = %d\n", slotCtx.ParentSlot)
	partitions := RentCollectionPartitions(slotCtx.ParentSlot, slotCtx.Slot, epochSchedule)
	pkRange := pubkeyRangeFromPartition(partitions[0])

	rentPubkeys := slotCtx.AccountsDb.KeysBetweenPrefixes(pkRange.StartPrefix, pkRange.EndPrefix)
	rentPubkeys = util.DedupePubkeys(rentPubkeys)

	accts := make([]*accounts.Account, 0)

	for _, pk := range rentPubkeys {
		acct, _ := collectRent(slotCtx, rent, pk)

		// TODO: logic for skip_rent_rewrites feature gate
		if acct != nil {
			accts = append(accts, acct)
		}
	}

	return accts
}
