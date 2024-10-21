package replay

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/cu"
	"go.firedancer.io/radiance/pkg/fees"
	"go.firedancer.io/radiance/pkg/sealevel"
	"k8s.io/klog/v2"
)

type TxErrInvalidSignature struct {
	msg string
}

func NewTxErrInvalidSignature(msg string) error {
	return &TxErrInvalidSignature{msg: msg}
}

func (err *TxErrInvalidSignature) Error() string {
	return err.msg
}

var (
	TxErrInsufficientFundsForRent = errors.New("TxErrInsufficientFundsForRent")
)

func transactionAcctsFromTx(slotCtx *sealevel.SlotCtx, tx *solana.Transaction) (*sealevel.TransactionAccounts, error) {
	acctsForTx := make([]accounts.Account, 0)

	txAcctMetas, err := tx.AccountMetaList()
	if err != nil {
		return nil, err
	}

	for _, acctMeta := range txAcctMetas {
		acct, err := slotCtx.GetAccount(acctMeta.PublicKey)
		if err != nil {
			return nil, err
		}
		acctsForTx = append(acctsForTx, *acct)
	}

	transactionAccts := sealevel.NewTransactionAccounts(acctsForTx)
	return transactionAccts, nil
}

func programIndices(tx *solana.Transaction, instrIdx int) []uint64 {
	idx := uint64(tx.Message.Instructions[instrIdx].ProgramIDIndex)
	return []uint64{idx}
}

func newExecCtx(slotCtx *sealevel.SlotCtx, transactionAccts *sealevel.TransactionAccounts, computeBudgetLimits *sealevel.ComputeBudgetLimits, log *sealevel.LogRecorder) *sealevel.ExecutionCtx {
	txCtx := sealevel.NewTestTransactionCtx(*transactionAccts, 64, 64)
	execCtx := &sealevel.ExecutionCtx{Log: log, TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(uint64(computeBudgetLimits.ComputeUnitLimit))}

	execCtx.GlobalCtx.Features = *slotCtx.Features
	execCtx.Accounts = accounts.NewMemAccounts()
	execCtx.SlotCtx = slotCtx
	execCtx.TransactionContext.ComputeBudgetLimits = computeBudgetLimits

	return execCtx
}

func instrsFromTx(tx *solana.Transaction) ([]sealevel.Instruction, error) {
	instrs := make([]sealevel.Instruction, len(tx.Message.Instructions))
	for idx, compiledInstr := range tx.Message.Instructions {
		programId, err := tx.ResolveProgramIDIndex(compiledInstr.ProgramIDIndex)
		if err != nil {
			return nil, err
		}

		ams, err := compiledInstr.ResolveInstructionAccounts(&tx.Message)
		if err != nil {
			return nil, err
		}

		var acctMetas []sealevel.AccountMeta
		for _, am := range ams {
			acctMeta := sealevel.AccountMeta{Pubkey: am.PublicKey, IsSigner: am.IsSigner, IsWritable: am.IsWritable}
			acctMetas = append(acctMetas, acctMeta)
		}

		instr := sealevel.Instruction{Accounts: acctMetas, ProgramId: programId, Data: compiledInstr.Data}
		instrs[idx] = instr
	}

	return instrs, nil
}

func fixupInstructionsSysvarAcct(execCtx *sealevel.ExecutionCtx, instrIdx uint16) error {
	instructionsSysvarIdx, err := execCtx.TransactionContext.IndexOfAccount(sealevel.SysvarInstructionsAddr)
	if err == nil {
		instructionsAcct, err := execCtx.TransactionContext.AccountAtIndex(instructionsSysvarIdx)
		if err != nil {
			return err
		}

		lastIndex := len(instructionsAcct.Data) - 2
		binary.LittleEndian.PutUint16(instructionsAcct.Data[lastIndex:], instrIdx)
		klog.Infof("found instructions sysvar pubkey at instr idx %d", instrIdx)
	}
	return nil
}

func ProcessTransaction(slotCtx *sealevel.SlotCtx, tx *solana.Transaction, txMeta *rpc.TransactionMeta) (uint64, error) {
	/*err := tx.VerifySignatures()
	if err != nil {
		return NewTxErrInvalidSignature(err.Error())
	}*/

	instrs, err := instrsFromTx(tx)
	if err != nil {
		return 0, err
	}

	err = sealevel.WriteInstructionsSysvar(&slotCtx.Accounts, instrs)
	if err != nil {
		return 0, err
	}

	transactionAccts, err := transactionAcctsFromTx(slotCtx, tx)
	if err != nil {
		return 0, err
	}

	computeBudgetLimits, err := sealevel.ComputeBudgetExecuteInstructions(instrs)
	if err != nil {
		return 0, err
	}

	var log sealevel.LogRecorder
	execCtx := newExecCtx(slotCtx, transactionAccts, computeBudgetLimits, &log)
	execCtx.TransactionContext.AllInstructions = instrs

	// check for pre-balance divergences
	for count := uint64(0); count < uint64(len(tx.Message.AccountKeys)); count++ {
		txAcct, err := execCtx.TransactionContext.Accounts.GetAccount(count)
		if err != nil {
			panic(fmt.Sprintf("unable to get tx acct %d whilst checking for pre-balances divergences", count))
		}
		if txAcct.Lamports != txMeta.PreBalances[count] {
			klog.Infof("tx %s pre-balance divergence: lamport balance for %s was %d but onchain lamport balance was %d (acct slot %d)", tx.Signatures[0], txAcct.Key, txAcct.Lamports, txMeta.PreBalances[count], txAcct.Slot)
		}
		execCtx.TransactionContext.Accounts.Unlock(count)
	}

	totalFee, payerNewLamports, err := fees.ApplyTxFees(tx, instrs, &execCtx.TransactionContext.Accounts, computeBudgetLimits)
	if err != nil {
		return 0, err
	}

	// check for fee divergences
	if totalFee != txMeta.Fee {
		klog.Infof("tx %s fee divergence: totalFee was %d, but onchain fee was %d", tx.Signatures[0], totalFee, txMeta.Fee)
	}

	rent, err := sealevel.ReadRentSysvar(execCtx)
	if err != nil {
		panic("failed to get and deserialize rent sysvar")
	}

	preTxRentStates := fees.NewRentStateInfo(&rent, execCtx.TransactionContext, tx)

	var instrErr error

	for instrIdx, instr := range tx.Message.Instructions {
		err = fixupInstructionsSysvarAcct(execCtx, uint16(instrIdx))
		if err != nil {
			return totalFee, err
		}

		resolvedAccountMetas, err := instr.ResolveInstructionAccounts(&tx.Message)
		if err != nil {
			return totalFee, err
		}

		var acctMetas []sealevel.AccountMeta
		for _, am := range resolvedAccountMetas {
			acctMeta := sealevel.AccountMeta{Pubkey: am.PublicKey, IsSigner: am.IsSigner, IsWritable: am.IsWritable}
			acctMetas = append(acctMetas, acctMeta)
		}

		instructionAccts := sealevel.InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

		err = execCtx.ProcessInstruction(instr.Data, instructionAccts, programIndices(tx, instrIdx))
		for _, l := range log.Logs {
			klog.Infof("%s", l)
		}
		if err != nil {
			klog.Infof("%+v", tx)
			instrErr = err
			break
		}
	}

	klog.Infof("[+] tx %s - compute units consumed: %d", tx.Signatures[0], execCtx.ComputeMeter.Used())

	// check for CU consumed divergences
	if instrErr == nil && *txMeta.ComputeUnitsConsumed != execCtx.ComputeMeter.Used() {
		klog.Infof("tx %s CU divergence: used was %d but onchain CU consumed was %d", tx.Signatures[0], execCtx.ComputeMeter.Used(), *txMeta.ComputeUnitsConsumed)
	}

	postTxRentStates := fees.NewRentStateInfo(&rent, execCtx.TransactionContext, tx)
	rentStateErr := fees.VerifyRentStateChanges(preTxRentStates, postTxRentStates, execCtx.TransactionContext)

	// check for post-balances divergences (but only if the tx succeeded)
	if instrErr == nil && rentStateErr == nil {
		for count := uint64(0); count < uint64(len(tx.Message.AccountKeys)); count++ {
			txAcct, err := execCtx.TransactionContext.Accounts.GetAccount(count)
			if err != nil {
				panic(fmt.Sprintf("unable to get tx acct %d whilst checking for post-balances divergences", count))
			}
			if txAcct.Lamports != txMeta.PostBalances[count] {
				klog.Infof("tx %s post-balance divergence: lamport balance for %s was %d but onchain lamport balance was %d", tx.Signatures[0], txAcct.Key, txAcct.Lamports, txMeta.PostBalances[count])
			}
			execCtx.TransactionContext.Accounts.Unlock(count)
		}
	}

	// if there was an error in the tx, do not update account states, except for deducting the tx fee
	// from the payer account
	if instrErr != nil || rentStateErr != nil {
		payerAcct, err := execCtx.TransactionContext.Accounts.GetAccount(0)
		if err != nil {
			panic(fmt.Sprintf("unable to get tx account to update payer acct state after failed tx: %s", err))
		}

		p, err := slotCtx.GetAccount(payerAcct.Key)
		if err != nil {
			panic(fmt.Sprintf("unable to get slot account to update payer acct state after failed tx: %s", err))
		}

		p.Lamports = payerNewLamports
		err = slotCtx.SetAccount(payerAcct.Key, p)
		if err != nil {
			panic(fmt.Sprintf("unable to set slot account to update state of payer acct after failed t: %s", err))
		}

		slotCtx.ModifiedAccts[payerAcct.Key] = true

		execCtx.TransactionContext.Accounts.Unlock(0)

		var txErr error
		if rentStateErr != nil {
			txErr = rentStateErr
		} else {
			txErr = instrErr
		}

		return totalFee, fmt.Errorf("tx err: %s", txErr)
	}

	// update account states in slotCtx for all accounts 'touched' during the tx's execution
	for idx, wasTouched := range execCtx.TransactionContext.Accounts.Touched {
		if wasTouched {
			newAcctState, err := execCtx.TransactionContext.Accounts.GetAccount(uint64(idx))
			if err != nil {
				panic(fmt.Sprintf("unable to get tx account to update state: %s", err))
			}

			err = slotCtx.SetAccount(newAcctState.Key, newAcctState)
			if err != nil {
				panic(fmt.Sprintf("unable to set slot account for %s to update state: %s", newAcctState.Key, err))
			}

			slotCtx.ModifiedAccts[newAcctState.Key] = true
			klog.Infof("modified account %s after tx", newAcctState.Key)
			execCtx.TransactionContext.Accounts.Unlock(uint64(idx))
		}
	}

	return totalFee, nil
}
