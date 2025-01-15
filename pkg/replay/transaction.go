package replay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/Overclock-Validator/mithril/pkg/accounts"
	"github.com/Overclock-Validator/mithril/pkg/cu"
	"github.com/Overclock-Validator/mithril/pkg/fees"
	"github.com/Overclock-Validator/mithril/pkg/rent"
	"github.com/Overclock-Validator/mithril/pkg/sealevel"
	"github.com/Overclock-Validator/mithril/pkg/util"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
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

	var programIdIdxs []uint64
	var instructionAccts []solana.PublicKey

	for _, instr := range tx.Message.Instructions {
		programIdIdxs = append(programIdIdxs, uint64(instr.ProgramIDIndex))
		ias, err := instr.ResolveInstructionAccounts(&tx.Message)
		if err != nil {
			panic("unable to resolve instruction accts")
		}
		for _, ia := range ias {
			instructionAccts = append(instructionAccts, ia.PublicKey)
		}
	}

	instructionAccts = util.DedupePubkeys(instructionAccts)

	for idx, acctMeta := range txAcctMetas {
		var acct *accounts.Account

		// in Agave client, if the account is designated as a program in the tx, then all the other fields
		// are their nil values instead of the actual values for the account
		if slices.Contains(programIdIdxs, uint64(idx)) && isNativeProgram(acctMeta.PublicKey) {
			acct = &accounts.Account{Key: acctMeta.PublicKey, Owner: sealevel.NativeLoaderAddr, Executable: true}
		} else if slices.Contains(programIdIdxs, uint64(idx)) && !acctMeta.IsWritable && !slices.Contains(instructionAccts, acctMeta.PublicKey) {
			tmp, err := slotCtx.GetAccount(acctMeta.PublicKey)
			if err != nil {
				return nil, err
			}
			acct = &accounts.Account{Key: acctMeta.PublicKey, Owner: tmp.Owner, Executable: true, IsDummy: true}
		} else {
			acct, err = slotCtx.GetAccount(acctMeta.PublicKey)
			if err != nil {
				return nil, err
			}
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
			acctMeta := sealevel.AccountMeta{Pubkey: am.PublicKey, IsSigner: am.IsSigner, IsWritable: isWritable(tx, am)}
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

func isWritable(tx *solana.Transaction, am *solana.AccountMeta) bool {
	if !am.IsWritable {
		return false
	}

	if isNativeProgram(am.PublicKey) || isSysvar(am.PublicKey) {
		return false
	}

	programIds, err := tx.GetProgramIDs()
	if err != nil {
		panic(err)
	}

	for _, programId := range programIds {
		if am.PublicKey == programId {
			return false
		}
	}

	return true
}

func isProgram(tx *solana.Transaction, am *solana.AccountMeta) bool {
	programIds, err := tx.GetProgramIDs()
	if err != nil {
		panic(err)
	}

	for _, programId := range programIds {
		if am.PublicKey == programId {
			return true
		}
	}

	return false
}

func acctsEqual(acct1 *accounts.Account, acct2 *accounts.Account) bool {
	return acct1.Lamports == acct2.Lamports &&
		acct1.Owner == acct2.Owner &&
		acct1.RentEpoch == acct2.RentEpoch &&
		acct1.Executable == acct2.Executable &&
		bytes.Equal(acct1.Data, acct2.Data)
}

func recordModifiedAccounts(slotCtx *sealevel.SlotCtx, execCtx *sealevel.ExecutionCtx) {
	// update account states in slotCtx for all accounts 'touched' during the tx's execution
	for idx, newAcctState := range execCtx.TransactionContext.Accounts.Accounts {
		if execCtx.TransactionContext.Accounts.Touched[idx] {
			err := slotCtx.SetAccount(newAcctState.Key, newAcctState)
			if err != nil {
				panic(fmt.Sprintf("unable to set slot account for %s to update state: %s", newAcctState.Key, err))
			}
			slotCtx.ModifiedAccts[newAcctState.Key] = true
			klog.Infof("modified account %s after tx", newAcctState.Key)
		}
	}
}

func handleFailedTxIfDurableTx(instrs []sealevel.Instruction, execCtx *sealevel.ExecutionCtx, slotCtx *sealevel.SlotCtx) (solana.PublicKey, bool) {
	instr := instrs[0]

	if instr.ProgramId == sealevel.SystemProgramAddr && len(instr.Data) >= 4 {
		decoder := bin.NewBinDecoder(instr.Data)

		instructionType, err := decoder.ReadUint32(bin.LE)
		if err != nil {
			return solana.PublicKey{}, false
		}

		if instructionType == sealevel.SystemProgramInstrTypeAdvanceNonceAccount {
			nonceAcctPk := instr.Accounts[0].Pubkey
			var nonceAcct *accounts.Account
			for _, acct := range execCtx.TransactionContext.Accounts.Accounts {
				if acct.Key == nonceAcctPk {
					nonceAcct = acct
					break
				}
			}

			if nonceAcct == nil {
				panic("nonce account not found in transaction accounts")
			}

			err = slotCtx.SetAccount(nonceAcctPk, nonceAcct)
			if err != nil {
				panic(fmt.Sprintf("error setting nonce account state after failed tx: %s\n", err))
			}

			return instr.Accounts[0].Pubkey, true
		}
	}

	return solana.PublicKey{}, false
}

func ProcessTransaction(slotCtx *sealevel.SlotCtx, tx *solana.Transaction, txMeta *rpc.TransactionMeta) (uint64, []solana.PublicKey, error) {
	/*err := tx.VerifySignatures()
	if err != nil {
		return NewTxErrInvalidSignature(err.Error())
	}*/

	instrs, err := instrsFromTx(tx)
	if err != nil {
		return 0, nil, err
	}

	err = sealevel.WriteInstructionsSysvar(&slotCtx.Accounts, instrs)
	if err != nil {
		return 0, nil, err
	}

	transactionAccts, err := transactionAcctsFromTx(slotCtx, tx)
	if err != nil {
		return 0, nil, err
	}

	computeBudgetLimits, err := sealevel.ComputeBudgetExecuteInstructions(instrs)
	if err != nil {
		return 0, nil, err
	}

	var log sealevel.LogRecorder
	execCtx := newExecCtx(slotCtx, transactionAccts, computeBudgetLimits, &log)
	execCtx.TransactionContext.AllInstructions = instrs
	execCtx.TransactionContext.Signature = tx.Signatures[0]

	// check for pre-balance divergences
	for count := uint64(0); count < uint64(len(tx.Message.AccountKeys)); count++ {
		txAcct, err := execCtx.TransactionContext.Accounts.GetAccount(count)
		if err != nil {
			panic(fmt.Sprintf("unable to get tx acct %d whilst checking for pre-balances divergences", count))
		}

		if !isNativeProgram(txAcct.Key) && !txAcct.IsDummy {
			if txAcct.Lamports != txMeta.PreBalances[count] {
				klog.Infof("tx %s pre-balance divergence: lamport balance for %s was %d but onchain lamport balance was %d\n%s", tx.Signatures[0], txAcct.Key, txAcct.Lamports, txMeta.PreBalances[count], util.PrettyPrintAcct(txAcct))
			}
		}

		execCtx.TransactionContext.Accounts.Unlock(count)
	}

	totalFee, payerNewLamports, err := fees.ApplyTxFees(tx, instrs, &execCtx.TransactionContext.Accounts, computeBudgetLimits)
	if err != nil {
		return totalFee, nil, nil
	}

	// check for fee divergences
	if totalFee != txMeta.Fee {
		klog.Infof("tx %s fee divergence: totalFee was %d, but onchain fee was %d", tx.Signatures[0], totalFee, txMeta.Fee)
	}

	rentSysvar, err := sealevel.ReadRentSysvar(execCtx)
	if err != nil {
		panic("failed to get and deserialize rent sysvar")
	}

	rent.MaybeSetRentExemptRentEpochMax(slotCtx, &rentSysvar, &execCtx.GlobalCtx.Features, &execCtx.TransactionContext.Accounts)
	preTxRentStates := rent.NewRentStateInfo(&rentSysvar, execCtx.TransactionContext, tx)

	for _, txAcct := range transactionAccts.Accounts {
		fmt.Printf("******** pre-tx acct: %s\n", util.PrettyPrintAcct(txAcct))
	}

	var instrErr error
	writablePubkeys := make([]solana.PublicKey, 0)

	for instrIdx, instr := range tx.Message.Instructions {
		err = fixupInstructionsSysvarAcct(execCtx, uint16(instrIdx))
		if err != nil {
			return totalFee, nil, err
		}

		resolvedAccountMetas, err := instr.ResolveInstructionAccounts(&tx.Message)
		if err != nil {
			return totalFee, nil, err
		}

		var acctMetas []sealevel.AccountMeta
		for _, am := range resolvedAccountMetas {
			acctMeta := sealevel.AccountMeta{Pubkey: am.PublicKey, IsSigner: am.IsSigner, IsWritable: isWritable(tx, am)}
			acctMetas = append(acctMetas, acctMeta)
			fmt.Printf("instr acct: %+v\n", acctMeta)
		}

		instructionAccts := sealevel.InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

		err = execCtx.ProcessInstruction(instr.Data, instructionAccts, programIndices(tx, instrIdx))
		for _, l := range log.Logs {
			klog.Infof("%s", l)
		}

		if err == nil {
			for _, am := range acctMetas {
				if am.IsWritable {
					writablePubkeys = append(writablePubkeys, am.Pubkey)
				}
			}
		} else {
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

	postTxRentStates := rent.NewRentStateInfo(&rentSysvar, execCtx.TransactionContext, tx)
	rentStateErr := rent.VerifyRentStateChanges(preTxRentStates, postTxRentStates, execCtx.TransactionContext)

	// check for post-balances divergences (but only if the tx succeeded)
	if instrErr == nil && rentStateErr == nil {
		for count := uint64(0); count < uint64(len(tx.Message.AccountKeys)); count++ {
			txAcct, err := execCtx.TransactionContext.Accounts.GetAccount(count)
			if err != nil {
				panic(fmt.Sprintf("unable to get tx acct %d whilst checking for post-balances divergences", count))
			}

			if !isNativeProgram(txAcct.Key) && !txAcct.IsDummy {
				if txAcct.Lamports != txMeta.PostBalances[count] {
					klog.Infof("tx %s post-balance divergence: lamport balance for %s was %d but onchain lamport balance was %d\n%s\n", tx.Signatures[0], txAcct.Key, txAcct.Lamports, txMeta.PostBalances[count], util.PrettyPrintAcct(txAcct))
				}
			}

			execCtx.TransactionContext.Accounts.Unlock(count)
		}
	}

	payerAcct, err := execCtx.TransactionContext.Accounts.GetAccount(0)
	if err != nil {
		panic(fmt.Sprintf("unable to get tx account to update payer acct state after failed tx: %s", err))
	}

	// if there was an error in the tx, do not update account states, except for deducting the tx fee
	// from the payer account
	if instrErr != nil || rentStateErr != nil {
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

		writableAcctsForFailedTx := make([]solana.PublicKey, 0)
		writableAcctsForFailedTx = append(writableAcctsForFailedTx, payerAcct.Key)

		noncePubkey, isDurableTx := handleFailedTxIfDurableTx(instrs, execCtx, slotCtx)
		if isDurableTx {
			writableAcctsForFailedTx = append(writableAcctsForFailedTx, noncePubkey)
		}

		var txErr error
		if rentStateErr != nil {
			txErr = rentStateErr
		} else {
			txErr = instrErr
		}

		return totalFee, writableAcctsForFailedTx, fmt.Errorf("tx err: %s", txErr)
	}

	recordModifiedAccounts(slotCtx, execCtx)
	writablePubkeys = append(writablePubkeys, payerAcct.Key)

	return totalFee, writablePubkeys, nil
}
