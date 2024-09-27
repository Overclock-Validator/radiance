package replay

import (
	"encoding/binary"

	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/cu"
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

// XXX: rewrite using tx.AccountMetaList()
func transactionAcctsAndAcctMetasFromTx(slotCtx *sealevel.SlotCtx, tx *solana.Transaction) (*sealevel.TransactionAccounts, error) {
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

func newExecCtx(slotCtx *sealevel.SlotCtx, transactionAccts *sealevel.TransactionAccounts, log *sealevel.LogRecorder) *sealevel.ExecutionCtx {
	txCtx := sealevel.NewTestTransactionCtx(*transactionAccts, 64, 64)

	execCtx := &sealevel.ExecutionCtx{Log: log, TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}

	execCtx.GlobalCtx.Features = *slotCtx.Features
	execCtx.Accounts = accounts.NewMemAccounts()
	execCtx.SlotCtx = slotCtx

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

func ProcessTransaction(slotCtx *sealevel.SlotCtx, tx *solana.Transaction) error {
	/*err := tx.VerifySignatures()
	if err != nil {
		return NewTxErrInvalidSignature(err.Error())
	}*/

	instrs, err := instrsFromTx(tx)
	if err != nil {
		return err
	}

	err = sealevel.WriteInstructionsSysvar(&slotCtx.Accounts, instrs)
	if err != nil {
		return err
	}

	transactionAccts, err := transactionAcctsAndAcctMetasFromTx(slotCtx, tx)
	if err != nil {
		return err
	}

	var log sealevel.LogRecorder
	execCtx := newExecCtx(slotCtx, transactionAccts, &log)

	computeBudgetLimits, err := sealevel.ComputeBudgetExecuteInstructions(instrs)
	if err != nil {
		return err
	}
	execCtx.TransactionContext.ComputeBudgetLimits = computeBudgetLimits

	for instrIdx, instr := range tx.Message.Instructions {
		err = fixupInstructionsSysvarAcct(execCtx, uint16(instrIdx))
		if err != nil {
			return err
		}

		resolvedAccountMetas, err := instr.ResolveInstructionAccounts(&tx.Message)
		if err != nil {
			return err
		}

		var acctMetas []sealevel.AccountMeta
		for _, am := range resolvedAccountMetas {
			acctMeta := sealevel.AccountMeta{Pubkey: am.PublicKey, IsSigner: am.IsSigner, IsWritable: am.IsWritable}
			acctMetas = append(acctMetas, acctMeta)
		}

		instructionAccts := sealevel.InstructionAcctsFromAccountMetas(acctMetas, *transactionAccts)
		err = execCtx.ProcessInstruction(instr.Data, instructionAccts, programIndices(tx, instrIdx))
		if err != nil {
			klog.Infof("%+v", tx)
			for _, l := range log.Logs {
				klog.Infof("%s", l)
			}
			return err
		}
	}

	// update account states in slotCtx for all accounts 'touched' during the tx's execution
	for idx, wasTouched := range execCtx.TransactionContext.Accounts.Touched {
		if wasTouched {
			newAcctState, _ := execCtx.TransactionContext.Accounts.GetAccount(uint64(idx))
			err = slotCtx.SetAccount(newAcctState.Key, newAcctState)
			if err != nil {
				return err
			}
			slotCtx.ModifiedAccts = append(slotCtx.ModifiedAccts, newAcctState)
			klog.Infof("modified account %s after tx", newAcctState.Key)
		}
	}

	return nil
}
