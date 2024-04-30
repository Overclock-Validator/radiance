package sealevel

import (
	"github.com/gagliardetto/solana-go"
	"github.com/ryanavella/wide"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/safemath"
)

type TxReturnData struct {
	programId solana.PublicKey
	data      []byte
}

type TransactionAccounts struct {
	Accounts []*accounts.Account
	Touched  []bool
}

type TransactionCtx struct {
	InstructionTrace         []InstructionCtx
	InstructionStack         []uint64
	RetData                  TxReturnData
	AccountKeys              []solana.PublicKey
	Accounts                 TransactionAccounts
	InstructionTraceCapacity uint64
	AccountsResizeDelta      int64
	Rent                     SysvarRent
}

func (txCtx *TransactionCtx) PushInstructionCtx(ixCtx InstructionCtx) {
	txCtx.InstructionTrace = append(txCtx.InstructionTrace, ixCtx)
}

func (txCtx *TransactionCtx) InstructionCtxStackHeight() uint64 {
	return uint64(len(txCtx.InstructionStack))
}

func (txCtx *TransactionCtx) CurrentInstructionCtx() (*InstructionCtx, error) {
	level, err := safemath.CheckedSubU64(txCtx.InstructionCtxStackHeight(), 1)
	if err != nil {
		return nil, InstrErrCallDepth
	}
	return &txCtx.InstructionTrace[level], nil
}

func (txCtx *TransactionCtx) ReturnData() (solana.PublicKey, []byte) {
	return txCtx.RetData.programId, txCtx.RetData.data
}

func (txCtx *TransactionCtx) KeyOfAccountAtIndex(index uint64) (solana.PublicKey, error) {
	if len(txCtx.AccountKeys) == 0 || index > uint64(len(txCtx.AccountKeys)-1) {
		return solana.PublicKey{}, SyscallErrNotEnoughAccountKeys
	}

	return txCtx.AccountKeys[index], nil
}

func (txCtx *TransactionCtx) SetReturnData(programId solana.PublicKey, data []byte) {
	txCtx.RetData.programId = programId
	txCtx.RetData.data = data
}

func (txCtx *TransactionCtx) IndexOfAccount(pubkey solana.PublicKey) (uint64, error) {
	for index, acctKey := range txCtx.AccountKeys {
		if acctKey == pubkey {
			return uint64(index), nil
		}
	}
	return 0, InstrErrMissingAccount
}

func (txCtx *TransactionCtx) NextInstructionCtx() (*InstructionCtx, error) {
	if len(txCtx.InstructionTrace) == 0 {
		return nil, InstrErrCallDepth
	}
	return &txCtx.InstructionTrace[len(txCtx.InstructionTrace)-1], nil
}

func (txCtx *TransactionCtx) InstructionCtxAtIndexInTrace(idxInTrace uint64) (*InstructionCtx, error) {
	if len(txCtx.InstructionTrace) == 0 || idxInTrace > uint64(len(txCtx.InstructionTrace)-1) {
		return nil, InstrErrCallDepth
	}
	return &txCtx.InstructionTrace[idxInTrace], nil
}

func (txCtx *TransactionCtx) InstructionTraceLength() uint64 {
	l := uint64(len(txCtx.InstructionTrace))
	return safemath.SaturatingSubU64(l, 1)
}

func (txCtx *TransactionCtx) InstructionCtxAtNestingLevel(nestingLevel uint64) (*InstructionCtx, error) {
	if len(txCtx.InstructionStack) == 0 || nestingLevel > uint64(len(txCtx.InstructionStack)-1) {
		return nil, InstrErrCallDepth
	}
	idxInTrace := txCtx.InstructionStack[nestingLevel]
	ixCtx, err := txCtx.InstructionCtxAtIndexInTrace(idxInTrace)
	if err != nil {
		return nil, err
	}
	return ixCtx, nil
}

func (txCtx *TransactionCtx) AccountAtIndex(idxInTx uint64) (*accounts.Account, error) {
	if len(txCtx.Accounts.Accounts) == 0 || idxInTx > uint64(len(txCtx.Accounts.Accounts)-1) {
		return nil, InstrErrNotEnoughAccountKeys
	}
	return txCtx.Accounts.Accounts[idxInTx], nil
}

func (txCtx *TransactionCtx) InstructionAccountsLamportSum(instrCtx *InstructionCtx) (wide.Uint128, error) {
	numInstrAccts := instrCtx.NumberOfInstructionAccounts()

	var instructionAcctsLamportSum wide.Uint128

	for instrAcctIdx := uint64(0); instrAcctIdx < numInstrAccts; instrAcctIdx++ {
		isDupe, _, err := instrCtx.IsInstructionAccountDuplicate(instrAcctIdx)
		if err != nil {
			return wide.NewUint128(0, 0), err
		}
		if isDupe {
			continue
		}

		idxInTx, err := instrCtx.IndexOfInstructionAccountInTransaction(instrAcctIdx)
		if err != nil {
			return wide.NewUint128(0, 0), err
		}

		acct, err := txCtx.AccountAtIndex(idxInTx)
		lamportsUint128 := wide.Uint128FromUint64(acct.Lamports)
		instructionAcctsLamportSum, err = safemath.CheckedAddU128(instructionAcctsLamportSum, lamportsUint128)
		if err != nil {
			return wide.NewUint128(0, 0), InstrErrArithmeticOverflow
		}
	}

	return instructionAcctsLamportSum, nil
}

func (txCtx *TransactionCtx) Push() error {
	nestingLevel := txCtx.InstructionCtxStackHeight()

	if len(txCtx.InstructionTrace) == 0 {
		return InstrErrCallDepth
	}

	callerInstrCtx := txCtx.InstructionTrace[len(txCtx.InstructionTrace)-1]
	calleeInstructionAccountsLamportSum, err := txCtx.InstructionAccountsLamportSum(&callerInstrCtx)
	if err != nil {
		return err
	}

	if len(txCtx.InstructionStack) != 0 {
		callerInstrCtx, err := txCtx.CurrentInstructionCtx()
		if err != nil {
			return err
		}

		originalCallerInstrAcctsLamportSum := callerInstrCtx.InstructionAccountsLamportSum
		currentCallerInstructionAccountsLamportSum, err := txCtx.InstructionAccountsLamportSum(callerInstrCtx)
		if err != nil {
			return err
		}

		if originalCallerInstrAcctsLamportSum.Cmp(currentCallerInstructionAccountsLamportSum) != 0 {
			return InstrErrUnbalancedInstruction
		}
	}

	nextInstrCtx, err := txCtx.NextInstructionCtx()
	if err != nil {
		return err
	}
	nextInstrCtx.NestingLevel = nestingLevel
	nextInstrCtx.InstructionAccountsLamportSum = calleeInstructionAccountsLamportSum

	idxInTrace := txCtx.InstructionTraceLength()
	if idxInTrace >= txCtx.InstructionTraceCapacity {
		return InstrErrCallDepth
	}

	txCtx.InstructionStack = append(txCtx.InstructionStack, idxInTrace)

	return nil
}

func (txCtx *TransactionCtx) Pop() error {
	if len(txCtx.InstructionStack) == 0 {
		return InstrErrCallDepth
	}

	currentInstrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	lamportsSum, err := txCtx.InstructionAccountsLamportSum(currentInstrCtx)
	if err != nil {
		return InstrErrUnbalancedInstruction
	}

	unbalanced := currentInstrCtx.InstructionAccountsLamportSum.Cmp(lamportsSum)

	// pop
	txCtx.InstructionStack = txCtx.InstructionStack[:len(txCtx.InstructionStack)-1]

	if unbalanced != 0 {
		return InstrErrUnbalancedInstruction
	}

	return nil
}

func (txAccounts *TransactionAccounts) GetAccount(idx uint64) (*accounts.Account, error) {
	if len(txAccounts.Accounts) == 0 || idx > (uint64(len(txAccounts.Accounts)-1)) {
		return nil, InstrErrMissingAccount
	}
	return txAccounts.Accounts[idx], nil
}

func (txAccounts *TransactionAccounts) Touch(idx uint64) error {
	if len(txAccounts.Touched) == 0 || idx > uint64(len(txAccounts.Touched)-1) {
		return InstrErrNotEnoughAccountKeys
	}
	txAccounts.Touched[idx] = true
	return nil
}
