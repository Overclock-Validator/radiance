package fees

import (
	"fmt"
	"math"

	"github.com/Overclock-Validator/mithril/pkg/accounts"
	"github.com/Overclock-Validator/mithril/pkg/accountsdb"
	"github.com/Overclock-Validator/mithril/pkg/safemath"
	"github.com/Overclock-Validator/mithril/pkg/sealevel"
	"github.com/gagliardetto/solana-go"
	"github.com/ryanavella/wide"
	"k8s.io/klog/v2"
)

const microLamportsPerLamport = 1000000

func calculatePriorityFee(computeBudgetLimits *sealevel.ComputeBudgetLimits) (uint64, error) {
	computeUnitPrice := wide.Uint128FromUint64(computeBudgetLimits.ComputeUnitPrice)
	computeUnitLimit := wide.Uint128FromUint64(uint64(computeBudgetLimits.ComputeUnitLimit))

	microLamportFee, err := safemath.CheckedMulU128(computeUnitPrice, computeUnitLimit)
	if err != nil {
		return 0, err
	}

	fee := safemath.SaturatingAddU128(microLamportFee, wide.Uint128FromUint64(microLamportsPerLamport-1)).Div(wide.Uint128FromUint64(microLamportsPerLamport))

	var priorityFee uint64
	if fee.IsUint64() {
		priorityFee = fee.Uint64()
	} else {
		priorityFee = math.MaxUint64
	}

	return priorityFee, nil
}

// There are currently two aspects of the tx fee cost model on Solana
// 1) fee per signature (5k lamports/sig)
// 2) prioritization fees set via a SetComputeUnitPrice instruction

const feePayerIdx = 0

func ApplyTxFees(tx *solana.Transaction, instrs []sealevel.Instruction, transactionAccts *sealevel.TransactionAccounts, computeBudgetLimits *sealevel.ComputeBudgetLimits) (uint64, uint64, error) {
	feePayerAcct, err := transactionAccts.GetAccount(feePayerIdx)
	if err != nil {
		panic("no fee payer")
	}
	defer transactionAccts.Unlock(feePayerIdx)

	numSignatures := uint64(tx.Message.Header.NumRequiredSignatures)

	// have to pay fees per signatures to these precompiles as well
	for _, instr := range instrs {
		if instr.ProgramId == sealevel.Secp256kPrecompileAddr || instr.ProgramId == sealevel.Ed25519PrecompileAddr {
			if len(instr.Data) == 0 {
				continue
			} else {
				numSignatures += uint64(instr.Data[0])
			}
		}
	}

	// basic tx fee. 5000 lamports per signature.
	baseTxFee := numSignatures * 5000

	// prioritization fees
	var priorityFee uint64
	if computeBudgetLimits.ComputeUnitPrice != 0 {
		priorityFee, err = calculatePriorityFee(computeBudgetLimits)
		if err != nil {
			return 0, 0, err
		}
	}

	totalTxFee, err := safemath.CheckedAddU64(baseTxFee, priorityFee)
	if err != nil {
		panic("overflow in calculating total tx fee")
	}

	if feePayerAcct.Lamports < totalTxFee {
		return totalTxFee, 0, sealevel.InstrErrInsufficientFunds
	}

	klog.Infof("tx fee: %d", totalTxFee)

	feePayerAcct.Lamports -= totalTxFee
	transactionAccts.Touch(feePayerIdx)

	return totalTxFee, feePayerAcct.Lamports, nil
}

func DistributeTxFeesToSlotLeader(acctsDb *accountsdb.AccountsDb, slotCtx *sealevel.SlotCtx, leader solana.PublicKey, totalFees uint64) {
	feesToBurn := totalFees / 2
	feesToLeader := totalFees - feesToBurn

	var leaderAcct *accounts.Account
	var err error

	leaderAcct, err = slotCtx.GetAccount(leader)
	if err != nil {
		// if leader didn't appear at all in the block, then retrieve its latest state from accountsdb instead
		leaderAcct, err = acctsDb.GetAccount(slotCtx.Slot, leader)
		if err != nil {
			panic(fmt.Sprintf("unable to get leader acct %s from both slotCtx and accountsdb", leader))
		}
	}

	leaderAcct.Lamports, err = safemath.CheckedAddU64(leaderAcct.Lamports, feesToLeader)
	if err != nil {
		panic("overflow when adding reward to slot leader balance")
	}

	err = slotCtx.SetAccount(leader, leaderAcct)
	if err != nil {
		panic(fmt.Sprintf("failed to SetAccount for leader acct %s when distributing tx fees", leader))
	}

	klog.Infof("calculated fees for leader: %d, post-balance: %d (%s)", feesToLeader, leaderAcct.Lamports, leader)
}
