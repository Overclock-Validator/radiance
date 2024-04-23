package sealevel

import (
	"errors"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"k8s.io/klog/v2"
)

const SystemProgMaxPermittedDataLen = 10 * 1024 * 1024

const (
	SystemProgramInstrTypeCreateAccount = iota
	SystemProgramInstrTypeAssign
	SystemProgramInstrTypeTransfer
	SystemProgramInstrTypeCreateAccountWithSeed
	SystemProgramInstrTypeAdvanceNonceAccount
	SystemProgramInstrTypeWithdrawNonceAccount
	SystemProgramInstrTypeInitializeNonceAccount
	SystemProgramInstrTypeAuthorizeNonceAccount
	SystemProgramInstrTypeAllocate
	SystemProgramInstrTypeAllocateWithSeed
	SystemProgramInstrTypeAssignWithSeed
	SystemProgramInstrTypeTransferWithSeed
	SystemProgramInstrTypeUpgradeNonceAccount
)

var (
	SystemProgErrAccountAlreadyInUse        = errors.New("SystemProgErrAccountAlreadyInUse")
	SystemProgErrInvalidAccountDataLength   = errors.New("SystemProgErrInvalidAccountDataLength")
	SystemProgErrResultWithNegativeLamports = errors.New("SystemProgErrResultWithNegativeLamports")
)

type SystemInstrCreateAccount struct {
	Lamports uint64
	Space    uint64
	Owner    solana.PublicKey
}

type SystemInstrAssign struct {
	Owner solana.PublicKey
}

type SystemInstrTransfer struct {
	Lamports uint64
}

type SystemInstrCreateAccountWithSeed struct {
	Base     solana.PublicKey
	Seed     string
	Lamports uint64
	Space    uint64
	Owner    solana.PublicKey
}

type SystemInstrWithdrawNonceAccount struct {
	Lamports uint64
}

type SystemInstrInitializeNonceAccount struct {
	Pubkey solana.PublicKey
}

type SystemInstrAuthorizeNonceAccount struct {
	Pubkey solana.PublicKey
}

type SystemInstrAllocate struct {
	Space uint64
}

type SystemInstrAllocateWithSeed struct {
	Base  solana.PublicKey
	Seed  string
	Space uint64
	Owner solana.PublicKey
}

type SystemInstrAssignWithSeed struct {
	Base  solana.PublicKey
	Seed  string
	Owner solana.PublicKey
}

type SystemInstrTransferWithSeed struct {
	Lamports  uint64
	FromSeed  string
	FromOwner solana.PublicKey
}

func checkWithinDeserializationLimit(decoder *bin.Decoder) error {
	if decoder.Position() > 1232 {
		return InstrErrInvalidInstructionData
	} else {
		return nil
	}
}

func (instr *SystemInstrCreateAccount) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error

	instr.Lamports, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	instr.Space, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	pk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(instr.Owner[:], pk)

	return checkWithinDeserializationLimit(decoder)
}

func (instr *SystemInstrAssign) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error

	pk, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(instr.Owner[:], pk)

	return checkWithinDeserializationLimit(decoder)
}

func (instr *SystemInstrTransfer) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error

	instr.Lamports, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	return checkWithinDeserializationLimit(decoder)
}

func (instr *SystemInstrCreateAccountWithSeed) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	base, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(instr.Base[:], base)

	instr.Seed, err = decoder.ReadRustString()
	if err != nil {
		return err
	}

	instr.Lamports, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	instr.Space, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	owner, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(instr.Owner[:], owner)

	return checkWithinDeserializationLimit(decoder)
}

func (instr *SystemInstrWithdrawNonceAccount) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	instr.Lamports, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	return checkWithinDeserializationLimit(decoder)
}

func (instr *SystemInstrInitializeNonceAccount) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	owner, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(instr.Pubkey[:], owner)
	return checkWithinDeserializationLimit(decoder)
}

func (instr *SystemInstrAuthorizeNonceAccount) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	owner, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(instr.Pubkey[:], owner)
	return checkWithinDeserializationLimit(decoder)
}

func (instr *SystemInstrAllocate) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	instr.Space, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	return checkWithinDeserializationLimit(decoder)
}

func (instr *SystemInstrAllocateWithSeed) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	base, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(instr.Base[:], base)

	instr.Seed, err = decoder.ReadRustString()
	if err != nil {
		return err
	}

	instr.Space, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	owner, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(instr.Owner[:], owner)

	return checkWithinDeserializationLimit(decoder)
}

func (instr *SystemInstrAssignWithSeed) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	base, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(instr.Base[:], base)

	instr.Seed, err = decoder.ReadRustString()
	if err != nil {
		return err
	}

	owner, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(instr.Owner[:], owner)
	return checkWithinDeserializationLimit(decoder)
}

func (instr *SystemInstrTransferWithSeed) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	instr.Lamports, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	instr.FromSeed, err = decoder.ReadRustString()
	if err != nil {
		return err
	}

	fromOwner, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(instr.FromOwner[:], fromOwner)

	return checkWithinDeserializationLimit(decoder)
}

func SystemProgramExecute(execCtx *ExecutionCtx) error {
	txCtx := execCtx.TransactionContext

	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	decoder := bin.NewBinDecoder(instrCtx.Data)

	instructionType, err := decoder.ReadUint32(bin.LE)
	if err != nil {
		return InstrErrInvalidInstructionData
	}

	signers, err := instrCtx.Signers(txCtx)
	if err != nil {
		return err
	}

	switch instructionType {

	case SystemProgramInstrTypeCreateAccount:
		{
			var createAccount SystemInstrCreateAccount
			err = createAccount.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			idx, err := instrCtx.IndexOfInstructionAccountInTransaction(1)
			if err != nil {
				return err
			}

			toAddr, err := txCtx.KeyOfAccountAtIndex(idx)
			if err != nil {
				return err
			}
			err = SystemProgramCreateAccount(execCtx, createAccount, toAddr, signers)
		}

	case SystemProgramInstrTypeAssign:
		{
			var assign SystemInstrAssign
			err = assign.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			// TODO: process Assign instruction
		}

	case SystemProgramInstrTypeTransfer:
		{
			var transfer SystemInstrTransfer
			err = transfer.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			// TODO: process Transfer instruction
		}

	case SystemProgramInstrTypeCreateAccountWithSeed:
		{
			var createAcctWithSeed SystemInstrCreateAccountWithSeed
			err = createAcctWithSeed.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			// TODO: process CreateAccountWithSeed instruction
		}

	case SystemProgramInstrTypeAdvanceNonceAccount:
		{
			// TODO: process AdvanceNonceAccount instruction
		}

	case SystemProgramInstrTypeWithdrawNonceAccount:
		{
			var withdrawNonceAcct SystemInstrWithdrawNonceAccount
			err = withdrawNonceAcct.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			// TODO: process WithdrawNonceAccount instruction
		}
	case SystemProgramInstrTypeInitializeNonceAccount:
		{
			var initNonceAcct SystemInstrInitializeNonceAccount
			err = initNonceAcct.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			// TODO: process InitializeNonceAccount instruction
		}

	case SystemProgramInstrTypeAuthorizeNonceAccount:
		{
			var authNonceAcct SystemInstrAuthorizeNonceAccount
			err = authNonceAcct.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			// TODO: process AuthorizeNonceAccount instruction
		}

	case SystemProgramInstrTypeAllocate:
		{
			var allocate SystemInstrAllocate
			err = allocate.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			// TODO: process Allocate instruction
		}

	case SystemProgramInstrTypeAllocateWithSeed:
		{
			var allocateWithSeed SystemInstrAllocateWithSeed
			err = allocateWithSeed.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			// TODO: process AllocateWithSeed instruction
		}

	case SystemProgramInstrTypeAssignWithSeed:
		{
			var assignWithSeed SystemInstrAssignWithSeed
			err = assignWithSeed.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			// TODO: process AssignWithSeed instruction
		}

	case SystemProgramInstrTypeTransferWithSeed:
		{
			var transferWithSeed SystemInstrTransferWithSeed
			err = transferWithSeed.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			// TODO: process TransferWithSeed instruction
		}

	case SystemProgramInstrTypeUpgradeNonceAccount:
		{
			// TODO: process UpgradeNonceAccount instruction
		}

	default:
		return InstrErrInvalidInstructionData
	}

	return err
}

func SystemProgramCreateAccount(execCtx *ExecutionCtx, createAcct SystemInstrCreateAccount, toAddr solana.PublicKey, signers []solana.PublicKey) error {
	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	err = instrCtx.CheckNumOfInstructionAccounts(2)
	if err != nil {
		return err
	}

	toAcct, err := instrCtx.BorrowInstructionAccount(txCtx, 1)
	if err != nil {
		return err
	}

	if toAcct.Lamports() > 0 {
		klog.Errorf("CreateAccount: account %s already in use (non-zero lamports)", toAddr)
		return SystemProgErrAccountAlreadyInUse
	}

	err = SystemProgramAllocateAndAssign(execCtx, toAcct, toAddr, createAcct.Space, createAcct.Owner, signers)
	if err != nil {
		return err
	}

	return SystemProgramTransfer(execCtx, 0, 1, createAcct.Lamports)
}

func SystemProgramAllocateAndAssign(execCtx *ExecutionCtx, toAcct *BorrowedAccount, toAddr solana.PublicKey, space uint64, owner solana.PublicKey, signers []solana.PublicKey) error {
	err := SystemProgramAllocate(execCtx, toAcct, toAddr, space, signers)
	if err != nil {
		return err
	}

	return SystemProgramAssign(execCtx, toAcct, toAddr, owner, signers)
}

func SystemProgramAllocate(execCtx *ExecutionCtx, acct *BorrowedAccount, address solana.PublicKey, space uint64, signers []solana.PublicKey) error {
	var isSigner bool
	for _, signer := range signers {
		if address == signer {
			isSigner = true
			break
		}
	}

	if !isSigner {
		klog.Errorf("Allocate: 'to' account %s must sign", address)
		return InstrErrMissingRequiredSignature
	}

	if len(acct.Data()) != 0 || acct.Owner() != solana.SystemProgramID {
		klog.Errorf("Allocate: account %s already in use", address)
		return SystemProgErrAccountAlreadyInUse
	}

	if space > SystemProgMaxPermittedDataLen {
		klog.Errorf("Allocate: requested %d, max allowed %d", space, SystemProgMaxPermittedDataLen)
		return SystemProgErrInvalidAccountDataLength
	}

	return acct.SetDataLength(space, execCtx.GlobalCtx.Features)
}

func SystemProgramAssign(execCtx *ExecutionCtx, acct *BorrowedAccount, address solana.PublicKey, owner solana.PublicKey, signers []solana.PublicKey) error {
	if acct.Owner() == owner {
		return nil
	}

	var isSigner bool
	for _, signer := range signers {
		if address == signer {
			isSigner = true
			break
		}
	}

	if !isSigner {
		klog.Errorf("Assign: account %s must sign", address)
		return InstrErrMissingRequiredSignature
	}

	return acct.SetOwner(execCtx.GlobalCtx.Features, owner)
}

func SystemProgramTransfer(execCtx *ExecutionCtx, fromAcctIdx uint64, toAcctIdx uint64, lamports uint64) error {
	instrCtx, err := execCtx.TransactionContext.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	isSigner, err := instrCtx.IsInstructionAccountSigner(fromAcctIdx)
	if err != nil {
		return err
	}

	if !isSigner {
		return InstrErrMissingRequiredSignature
	}

	return transferInternal(execCtx, fromAcctIdx, toAcctIdx, lamports)
}

func transferInternal(execCtx *ExecutionCtx, fromAcctIdx uint64, toAcctIdx uint64, lamports uint64) error {
	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	from, err := instrCtx.BorrowInstructionAccount(txCtx, fromAcctIdx)
	if err != nil {
		return err
	}

	if len(from.Data()) != 0 {
		klog.Errorf("Transfer: 'from' must not carry data")
		return InstrErrInvalidArgument
	}

	if lamports > from.Lamports() {
		klog.Errorf("Transfer: insufficient lamports %d, need %d", from.Lamports(), lamports)
		return SystemProgErrResultWithNegativeLamports
	}

	f := execCtx.GlobalCtx.Features
	err = from.CheckedSubLamports(lamports, f)
	if err != nil {
		return err
	}

	to, err := instrCtx.BorrowInstructionAccount(txCtx, toAcctIdx)
	if err != nil {
		return err
	}

	return to.CheckedAddLamports(lamports, f)
}
