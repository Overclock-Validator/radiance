package sealevel

import (
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/cu"
	"go.firedancer.io/radiance/pkg/global"
	"k8s.io/klog/v2"
)

type ExecutionCtx struct {
	Log                  Logger
	Accounts             accounts.Accounts
	TransactionContext   *TransactionCtx
	GlobalCtx            global.GlobalCtx
	ComputeMeter         cu.ComputeMeter
	SysvarCache          SysvarCache
	Blockhash            [32]byte
	LamportsPerSignature uint64
	SlotCtx              *SlotCtx
}

type SlotCtx struct {
	Accounts accounts.Accounts
	Slot     uint64
}

func (execCtx *ExecutionCtx) PrepareInstruction(ix Instruction, signers []solana.PublicKey) ([]InstructionAccount, []uint64, error) {

	txCtx := execCtx.TransactionContext

	ixCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return nil, nil, err
	}

	dedupInstructionAccounts := make([]InstructionAccount, 0)
	duplicateIndices := make([]uint64, len(ix.Accounts))

	for instructionAcctIndex, accountMeta := range ix.Accounts {
		indexInTx, err := txCtx.IndexOfAccount(accountMeta.Pubkey)
		if err != nil {
			klog.Error("instruction references unknown account %s", accountMeta.Pubkey)
			return nil, nil, err
		}

		duplicateIndex := -1
		for index, instrAcct := range dedupInstructionAccounts {
			if instrAcct.IndexInTransaction == indexInTx {
				duplicateIndex = index
				break
			}
		}

		if duplicateIndex != -1 {
			duplicateIndices = append(duplicateIndices, uint64(duplicateIndex))
			if duplicateIndex > len(dedupInstructionAccounts)-1 {
				return nil, nil, InstrErrNotEnoughAccountKeys
			}
			instructionAcct := dedupInstructionAccounts[duplicateIndex]
			instructionAcct.IsSigner = instructionAcct.IsSigner || accountMeta.IsSigner
			instructionAcct.IsWritable = instructionAcct.IsWritable || accountMeta.IsWritable
		} else {
			indexInCaller, err := ixCtx.IndexOfInstructionAccount(txCtx, accountMeta.Pubkey)
			if err != nil {
				return nil, nil, err // InstructionError::MissingAccount
			}
			duplicateIndices = append(duplicateIndices, uint64(len(dedupInstructionAccounts)))

			instrAcct := InstructionAccount{IndexInTransaction: indexInTx,
				IndexInCaller: indexInCaller,
				IndexInCallee: uint64(instructionAcctIndex),
				IsSigner:      accountMeta.IsSigner,
				IsWritable:    accountMeta.IsWritable}

			dedupInstructionAccounts = append(dedupInstructionAccounts, instrAcct)
		}
	}

	for _, instructionAcct := range dedupInstructionAccounts {
		borrowedAcct, err := ixCtx.BorrowInstructionAccount(txCtx, instructionAcct.IndexInCaller)
		if err != nil {
			return nil, nil, err
		}

		// "Read-only in caller cannot become writable in callee"
		if instructionAcct.IsWritable && !borrowedAcct.IsWritable() {
			return nil, nil, InstrErrPrivilegeEscalation
		}

		// "To be signed in the callee,
		// it must be either signed in the caller or by the program"
		presentInSigners := false
		for _, addr := range signers {
			if addr == borrowedAcct.Key() {
				presentInSigners = true
				break
			}
		}
		if instructionAcct.IsSigner && !(borrowedAcct.IsSigner() || presentInSigners) {
			return nil, nil, InstrErrPrivilegeEscalation
		}
	}

	var instructionAccounts []InstructionAccount
	for _, duplicateIndex := range duplicateIndices {
		if duplicateIndex > uint64(len(dedupInstructionAccounts)-1) {
			return nil, nil, InstrErrNotEnoughAccountKeys
		}
		instrAcct := dedupInstructionAccounts[duplicateIndex]
		instructionAccounts = append(instructionAccounts, instrAcct)
	}

	// "Find and validate executables / program accounts"
	calleeProgramId := ix.ProgramId
	programAcctIdx, err := ixCtx.IndexOfInstructionAccount(txCtx, calleeProgramId)
	if err != nil {
		klog.Errorf("unknown program %s", calleeProgramId)
		return nil, nil, err
	}

	borrowedProgramAcct, err := ixCtx.BorrowInstructionAccount(txCtx, programAcctIdx)
	if err != nil {
		return nil, nil, err
	}

	if !borrowedProgramAcct.IsExecutable() {
		klog.Errorf("account %s is not executable", calleeProgramId)
		return nil, nil, InstrErrAccountNotExecutable
	}

	return instructionAccounts, []uint64{borrowedProgramAcct.IndexInTransaction}, nil
}

func (execCtx *ExecutionCtx) ProcessInstruction(instrData []byte, instructionAccts []InstructionAccount, programIndices []uint64) error {
	nextInstrCtx, err := execCtx.TransactionContext.NextInstructionCtx()
	if err != nil {
		return err
	}

	nextInstrCtx.ProgramAccounts = programIndices
	nextInstrCtx.InstructionAccounts = instructionAccts
	nextInstrCtx.Data = instrData

	err = execCtx.Push()
	if err != nil {
		return err
	}

	err1 := execCtx.ExecuteInstruction()

	err2 := execCtx.Pop()

	if err1 != nil {
		return err1
	} else if err2 != nil {
		return err2
	}

	return nil
}

func (execCtx *ExecutionCtx) ExecuteInstruction() error {
	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	borrowedRootAccount, err := instrCtx.BorrowProgramAccount(txCtx, 0)
	if err != nil {
		return InstrErrUnsupportedProgramId
	}

	ownerId := borrowedRootAccount.Owner()

	var builtinId solana.PublicKey
	if ownerId == NativeLoaderAddr {
		builtinId = borrowedRootAccount.Key()
	} else {
		builtinId = ownerId
	}

	nativeProgramFn, err := resolveNativeProgramById(builtinId)
	if err == IsPrecompile {
		// TODO: handle precompile calls (ed25519, secp256k)
		return InstrErrUnsupportedProgramId
	} else if err != nil { // unrecognised builtin
		return err
	}

	err = nativeProgramFn(execCtx)

	// TODO: other error handling

	return err
}

func (execCtx *ExecutionCtx) Push() error {
	txCtx := execCtx.TransactionContext

	idx := txCtx.InstructionTraceLength()
	ixCtx, err := txCtx.InstructionCtxAtIndexInTrace(idx)
	if err != nil {
		return err
	}

	programId, err := ixCtx.LastProgramKey(txCtx)
	if err != nil {
		return InstrErrUnsupportedProgramId
	}

	if txCtx.InstructionCtxStackHeight() != 0 {
		var contains bool
		for level := uint64(0); level < txCtx.InstructionCtxStackHeight(); level++ {
			ic, err := txCtx.InstructionCtxAtNestingLevel(level)
			if err == nil {
				programAcct, err := ic.BorrowLastProgramAccount(txCtx)
				if err == nil {
					if programAcct.Key() == programId {
						contains = true
						break
					}
				}
			}
		}

		var isLast bool
		ic, err := txCtx.CurrentInstructionCtx()
		if err != nil {
			return err
		}
		programAcct, err := ic.BorrowLastProgramAccount(txCtx)
		if err == nil {
			if programAcct.Key() == programId {
				isLast = true
			}
		}

		if contains && !isLast {
			return InstrErrReentrancyNotAllowed
		}
	}

	err = txCtx.Push()
	return err
}

func (execCtx *ExecutionCtx) Pop() error {
	return execCtx.TransactionContext.Pop()
}

func (execCtx *ExecutionCtx) StackHeight() uint64 {
	return execCtx.TransactionContext.InstructionCtxStackHeight()
}

func (execCtx *ExecutionCtx) NativeInvoke(instruction Instruction, signers []solana.PublicKey) error {
	instrAccts, programIndices, err := execCtx.PrepareInstruction(instruction, signers)
	if err != nil {
		return err
	}
	err = execCtx.ProcessInstruction(instruction.Data, instrAccts, programIndices)
	return err
}

func (slotCtx *SlotCtx) GetAccount(pubkey solana.PublicKey) (*accounts.Account, error) {
	pk := [32]byte(pubkey)
	acct, err := slotCtx.Accounts.GetAccount(&pk)
	if err != nil {
		return nil, err
	} else {
		return acct, nil
	}
}
