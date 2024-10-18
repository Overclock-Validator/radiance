package fees

import (
	"fmt"

	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/sealevel"
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
