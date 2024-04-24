package sealevel

import (
	"bytes"
	"crypto/sha256"
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
	SystemProgErrAddressWithSeedMismatch    = errors.New("SystemProgErrAddressWithSeedMismatch")
	SystemProgErrNonceNoRecentBlockhashes   = errors.New("SystemProgErrNonceNoRecentBlockhashes")
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

const (
	NonceVersionLegacy  = 0
	NonceVersionCurrent = 1
)

type NonceStateVersions struct {
	Type    uint32
	Legacy  NonceData
	Current NonceData
}

type NonceData struct {
	IsInitialized bool
	Authority     solana.PublicKey
	DurableNonce  [32]byte
	FeeCalculator FeeCalculator
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

func (nonceStateVersions *NonceStateVersions) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	nonceStateVersions.Type, err = decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
	}

	switch nonceStateVersions.Type {
	case NonceVersionLegacy:
		{
			err = nonceStateVersions.Legacy.UnmarshalWithDecoder(decoder)
		}
	case NonceVersionCurrent:
		{
			err = nonceStateVersions.Current.UnmarshalWithDecoder(decoder)
		}
	default:
		err = InstrErrInvalidAccountData
	}

	return err
}

func (nonceStateVersions *NonceStateVersions) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(buf)

	err := encoder.WriteUint32(nonceStateVersions.Type, bin.LE)
	if err != nil {
		return nil, err
	}

	var nonceDataBytes []byte
	if nonceStateVersions.Type == NonceVersionLegacy {
		nonceDataBytes, err = nonceStateVersions.Legacy.Marshal()
		if err != nil {
			return nil, err
		}
	} else if nonceStateVersions.Type == NonceVersionCurrent {
		nonceDataBytes, err = nonceStateVersions.Current.Marshal()
		if err != nil {
			return nil, err
		}
	} else {
		panic("NonceStateVersions in an invalid state - programming error")
	}

	buf.Write(nonceDataBytes)

	return buf.Bytes(), nil
}

func (nonceStateVersions *NonceStateVersions) State() *NonceData {
	if nonceStateVersions.Type == NonceVersionLegacy {
		return &nonceStateVersions.Legacy
	} else if nonceStateVersions.Type == NonceVersionCurrent {
		return &nonceStateVersions.Current
	} else {
		panic("NonceStateVersions in an invalid state - programming error")
	}
}

func (nonceData *NonceData) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	isInitialized, err := decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
	}

	if isInitialized == 1 {
		authority, err := decoder.ReadBytes(solana.PublicKeyLength)
		if err != nil {
			return err
		}
		copy(nonceData.Authority[:], authority)

		durableNonce, err := decoder.ReadBytes(32)
		if err != nil {
			return err
		}
		copy(nonceData.DurableNonce[:], durableNonce)

		lamportsPerSig, err := decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}
		nonceData.FeeCalculator.LamportsPerSignature = lamportsPerSig
		nonceData.IsInitialized = true
	}
	return nil
}

func (nonceData *NonceData) Marshal() ([]byte, error) {
	var err error

	buf := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(buf)

	if !nonceData.IsInitialized {
		err = encoder.WriteUint32(0, bin.LE)
		if err != nil {
			return nil, err
		}
	} else {
		err = encoder.WriteUint32(1, bin.LE)
		if err != nil {
			return nil, err
		}
		err = encoder.WriteBytes(nonceData.Authority[:], false)
		if err != nil {
			return nil, err
		}
		err = encoder.WriteBytes(nonceData.DurableNonce[:], false)
		if err != nil {
			return nil, err
		}
		err = encoder.WriteUint64(nonceData.FeeCalculator.LamportsPerSignature, bin.LE)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func (nonceData *NonceData) IsSignerAuthority(signers []solana.PublicKey) bool {
	for _, signer := range signers {
		if nonceData.Authority == signer {
			return true
		}
	}
	return false
}

func (nonceData *NonceData) ChangeAuthority(newAuthority solana.PublicKey) {
	nonceData.Authority = newAuthority
}

func extractAddress(txCtx *TransactionCtx, instrCtx *InstructionCtx, instrAcctIdx uint64) (solana.PublicKey, error) {
	var addr solana.PublicKey
	var err error

	idx, err := instrCtx.IndexOfInstructionAccountInTransaction(instrAcctIdx)
	if err != nil {
		return addr, err
	}

	addr, err = txCtx.KeyOfAccountAtIndex(idx)
	return addr, err
}

func extractAddressWithSeed(txCtx *TransactionCtx, instrCtx *InstructionCtx, instrAcctIdx uint64, base solana.PublicKey, seed string, owner solana.PublicKey) (solana.PublicKey, error) {
	var addr solana.PublicKey
	var err error

	idx, err := instrCtx.IndexOfInstructionAccountInTransaction(instrAcctIdx)
	if err != nil {
		return addr, err
	}

	addr, err = txCtx.KeyOfAccountAtIndex(idx)
	if err != nil {
		return addr, err
	}

	addrWithSeed, err := solana.CreateWithSeed(base, seed, owner)
	if err != nil {
		return addr, err
	}
	if addr != addrWithSeed {
		klog.Errorf("Create: address %s does not match derived address %s", addr, addrWithSeed)
		return addr, SystemProgErrAddressWithSeedMismatch
	}
	return addr, err
}

func SystemProgramExecute(execCtx *ExecutionCtx) error {
	err := execCtx.ComputeMeter.Consume(CUSystemProgramDefaultComputeUnits)
	if err != nil {
		return err
	}

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
			err = instrCtx.CheckNumOfInstructionAccounts(2)
			if err != nil {
				return err
			}
			toAddr, err := extractAddress(txCtx, instrCtx, 1)
			if err != nil {
				return err
			}
			err = SystemProgramCreateAccount(execCtx, toAddr, createAccount.Lamports, createAccount.Space, createAccount.Owner, signers)
		}

	case SystemProgramInstrTypeAssign:
		{
			var assign SystemInstrAssign
			err = assign.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			err = instrCtx.CheckNumOfInstructionAccounts(1)
			if err != nil {
				return err
			}
			acct, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
			if err != nil {
				return err
			}
			addr, err := extractAddress(txCtx, instrCtx, 0)
			if err != nil {
				return err
			}
			err = SystemProgramAssign(execCtx, acct, addr, assign.Owner, signers)
		}

	case SystemProgramInstrTypeTransfer:
		{
			var transfer SystemInstrTransfer
			err = transfer.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			err = instrCtx.CheckNumOfInstructionAccounts(2)
			if err != nil {
				return err
			}
			err = SystemProgramTransfer(execCtx, 0, 1, transfer.Lamports)
		}

	case SystemProgramInstrTypeCreateAccountWithSeed:
		{
			var createAcctWithSeed SystemInstrCreateAccountWithSeed
			err = createAcctWithSeed.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			err = instrCtx.CheckNumOfInstructionAccounts(2)
			if err != nil {
				return err
			}
			toAddr, err := extractAddressWithSeed(txCtx, instrCtx, 1, createAcctWithSeed.Base, createAcctWithSeed.Seed, createAcctWithSeed.Owner)
			if err != nil {
				return err
			}
			err = SystemProgramCreateAccount(execCtx, toAddr, createAcctWithSeed.Lamports, createAcctWithSeed.Space, createAcctWithSeed.Owner, signers)
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
			err = instrCtx.CheckNumOfInstructionAccounts(1)
			if err != nil {
				return err
			}
			acct, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
			if err != nil {
				return err
			}
			recentBlockHashes, err := ReadRecentBlockHashesSysvar(execCtx, instrCtx, 1)
			if err != nil {
				return err
			}
			if len(*recentBlockHashes) == 0 {
				return SystemProgErrNonceNoRecentBlockhashes
			}

			// TODO: replace with reading rent sysvar from sysvar cache
			err = checkAcctForRentSysvar(txCtx, instrCtx, 2)
			if err != nil {
				return err
			}
			rent := ReadRentSysvar(&execCtx.Accounts)

			err = SystemProgramInitializeNonceAccount(execCtx, acct, initNonceAcct.Pubkey, &rent)
		}

	case SystemProgramInstrTypeAuthorizeNonceAccount:
		{
			var authNonceAcct SystemInstrAuthorizeNonceAccount
			err = authNonceAcct.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			err = instrCtx.CheckNumOfInstructionAccounts(1)
			if err != nil {
				return err
			}
			acct, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
			if err != nil {
				return err
			}
			err = SystemProgramAuthorizeNonceAccount(execCtx, acct, authNonceAcct.Pubkey, signers)
		}

	case SystemProgramInstrTypeAllocate:
		{
			var allocate SystemInstrAllocate
			err = allocate.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			err = instrCtx.CheckNumOfInstructionAccounts(1)
			if err != nil {
				return err
			}
			acct, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
			if err != nil {
				return err
			}
			addr, err := extractAddress(txCtx, instrCtx, 0)
			if err != nil {
				return err
			}
			err = SystemProgramAllocate(execCtx, acct, addr, allocate.Space, signers)
		}

	case SystemProgramInstrTypeAllocateWithSeed:
		{
			var allocateWithSeed SystemInstrAllocateWithSeed
			err = allocateWithSeed.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			err = instrCtx.CheckNumOfInstructionAccounts(1)
			if err != nil {
				return err
			}
			acct, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
			if err != nil {
				return err
			}
			addr, err := extractAddressWithSeed(txCtx, instrCtx, 0, allocateWithSeed.Base, allocateWithSeed.Seed, allocateWithSeed.Owner)
			if err != nil {
				return err
			}
			err = SystemProgramAllocateAndAssign(execCtx, acct, addr, allocateWithSeed.Space, allocateWithSeed.Owner, signers)
		}

	case SystemProgramInstrTypeAssignWithSeed:
		{
			var assignWithSeed SystemInstrAssignWithSeed
			err = assignWithSeed.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			err = instrCtx.CheckNumOfInstructionAccounts(1)
			if err != nil {
				return err
			}
			acct, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
			if err != nil {
				return err
			}
			addr, err := extractAddressWithSeed(txCtx, instrCtx, 0, assignWithSeed.Base, assignWithSeed.Seed, assignWithSeed.Owner)
			err = SystemProgramAssign(execCtx, acct, addr, assignWithSeed.Owner, signers)
		}

	case SystemProgramInstrTypeTransferWithSeed:
		{
			var transferWithSeed SystemInstrTransferWithSeed
			err = transferWithSeed.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}
			err = instrCtx.CheckNumOfInstructionAccounts(3)
			if err != nil {
				return err
			}
			err = SystemProgramTransferWithSeed(execCtx, 0, 1, transferWithSeed.FromSeed, transferWithSeed.FromOwner, 2, transferWithSeed.Lamports)

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

func SystemProgramCreateAccount(execCtx *ExecutionCtx, toAddr solana.PublicKey, lamports uint64, space uint64, owner solana.PublicKey, signers []solana.PublicKey) error {
	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
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

	err = SystemProgramAllocateAndAssign(execCtx, toAcct, toAddr, space, owner, signers)
	if err != nil {
		return err
	}

	return SystemProgramTransfer(execCtx, 0, 1, lamports)
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

func SystemProgramTransferWithSeed(execCtx *ExecutionCtx, fromAcctIdx uint64, fromBaseAcctIdx uint64, fromSeed string, fromOwner solana.PublicKey, toAcctIdx uint64, lamports uint64) error {
	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	isSigner, err := instrCtx.IsInstructionAccountSigner(fromBaseAcctIdx)
	if err != nil {
		return err
	}
	if !isSigner {
		klog.Errorf("Transfer: from account must sign")
		return InstrErrMissingRequiredSignature
	}

	base, err := txCtx.KeyOfAccountAtIndex(fromBaseAcctIdx)
	if err != nil {
		return err
	}

	addrFromSeed, err := solana.CreateWithSeed(base, fromSeed, fromOwner)
	if err != nil {
		return err
	}

	fromAddr, err := extractAddress(txCtx, instrCtx, fromAcctIdx)
	if err != nil {
		return err
	}

	if fromAddr != addrFromSeed {
		klog.Errorf("Transfer: from address %s does not match derived address %s", fromAddr, addrFromSeed)
		return SystemProgErrAddressWithSeedMismatch
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

func durableNonce(hash [32]byte) [32]byte {
	prefix := "DURABLE_NONCE"
	hasher := sha256.New()
	hasher.Write([]byte(prefix))
	sum := hasher.Sum(hash[:])

	var result [32]byte
	copy(result[:], sum)
	return result
}

func SystemProgramInitializeNonceAccount(execCtx *ExecutionCtx, acct *BorrowedAccount, nonceAuthority solana.PublicKey, rent *SysvarRent) error {
	if !acct.IsWritable() {
		klog.Errorf("Initialize nonce account: account %s must be writable", acct.Key())
		return InstrErrInvalidArgument
	}

	decoder := bin.NewBinDecoder(acct.Data())

	var nonceStateVersions NonceStateVersions
	err := nonceStateVersions.UnmarshalWithDecoder(decoder)
	if err != nil {
		return InstrErrInvalidAccountData
	}

	switch nonceStateVersions.State().IsInitialized {
	case false:
		{
			minBalance := rent.MinimumBalance(uint64(len(acct.Data())))
			if acct.Lamports() < minBalance {
				klog.Errorf("initialize nonce account: insufficient lamports %d, need %d", acct.Lamports(), minBalance)
				return InstrErrInsufficientFunds
			}

			durableNonce := durableNonce(execCtx.Blockhash)

			newNonceStateVersions := NonceStateVersions{Type: NonceVersionCurrent, Current: NonceData{
				Authority:     nonceAuthority,
				DurableNonce:  durableNonce,
				FeeCalculator: FeeCalculator{LamportsPerSignature: execCtx.LamportsPerSignature},
			}}

			newStateBytes, err := newNonceStateVersions.Marshal()
			if err != nil {
				return err
			}

			err = acct.SetData(execCtx.GlobalCtx.Features, newStateBytes)
		}
	case true:
		{
			klog.Errorf("Initialize nonce account: Account %s state is invalid. Already initialized.", acct.Key())
			err = InstrErrInvalidAccountData
		}
	}
	return err
}

func SystemProgramAuthorizeNonceAccount(execCtx *ExecutionCtx, acct *BorrowedAccount, nonceAuthority solana.PublicKey, signers []solana.PublicKey) error {
	if !acct.IsWritable() {
		klog.Errorf("Authorize nonce account: Account %s must be writeable", acct.Key())
		return InstrErrInvalidArgument
	}

	decoder := bin.NewBinDecoder(acct.Data())

	var nonceStateVersions NonceStateVersions
	err := nonceStateVersions.UnmarshalWithDecoder(decoder)
	if err != nil {
		return InstrErrInvalidAccountData
	}

	nonceData := nonceStateVersions.State()
	if !nonceData.IsInitialized {
		klog.Errorf("Authorize nonce account: account %s state invalid (uninitialized)", acct.Key())
		return InstrErrInvalidAccountData
	}

	if !nonceData.IsSignerAuthority(signers) {
		return InstrErrMissingRequiredSignature
	}

	nonceData.ChangeAuthority(nonceAuthority)

	newStateData, err := nonceStateVersions.Marshal()
	if err != nil {
		return err
	}
	return acct.SetData(execCtx.GlobalCtx.Features, newStateData)
}
