package sealevel

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/base58"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/safemath"
	"go.firedancer.io/radiance/pkg/sbpf"
)

const (
	MaxSigners                = 16
	MaxCpiInstructionDataLen  = 10 * 1024
	MaxCpiInstructionAccounts = 255
	MaxCpiAccountInfos        = 128
)

func checkInstructionSize(execCtx *ExecutionCtx, numAccounts uint64, dataLen uint64) error {
	if execCtx.GlobalCtx.Features.IsActive(features.LoosenCpiSizeRestriction) {
		if dataLen > MaxCpiInstructionDataLen {
			return SyscallErrMaxInstructionDataLenExceeded
		}

		if numAccounts > MaxCpiInstructionAccounts {
			return SyscallErrMaxInstructionAccountsExceeded
		}
	} else {
		size := safemath.SaturatingAddU64(safemath.SaturatingMulU64(numAccounts, AccountMetaSize), dataLen)
		if size > CUMaxCpiInstructionSize {
			return SyscallErrInstructionTooLarge
		}
	}
	return nil
}

func translateInstructionC(vm sbpf.VM, addr uint64) (Instruction, error) {
	ixData, err := vm.Translate(addr, SolInstructionCStructSize, false)
	if err != nil {
		return Instruction{}, err
	}

	byteReader := bytes.NewReader(ixData)
	var ix SolInstructionC

	err = ix.Unmarshal(byteReader)
	if err != nil {
		return Instruction{}, err
	}

	err = checkInstructionSize(executionCtx(vm), ix.AccountsLen, ix.DataLen)
	if err != nil {
		return Instruction{}, err
	}

	pkData, err := vm.Translate(ix.ProgramIdAddr, solana.PublicKeyLength, false)
	if err != nil {
		return Instruction{}, err
	}
	programId := solana.PublicKeyFromBytes(pkData)

	accountMetasData, err := vm.Translate(ix.AccountsAddr, SolAccountMetaCSize*ix.AccountsLen, false)
	if err != nil {
		return Instruction{}, err
	}

	byteReader.Reset(accountMetasData)

	var accountMetas []SolAccountMetaC
	for count := uint64(0); count < ix.AccountsLen; count++ {
		var am SolAccountMetaC
		err = am.Unmarshal(byteReader)
		if err != nil {
			return Instruction{}, err
		}
		accountMetas = append(accountMetas, am)
	}

	// TODO: do CU accounting for `loosen_cpi_size_restriction` feature gate

	data, err := vm.Translate(ix.DataAddr, ix.DataLen, false)
	if err != nil {
		return Instruction{}, err
	}

	accounts := make([]AccountMeta, ix.AccountsLen)
	for count := uint64(0); count < ix.AccountsLen; count++ {
		accountMeta := accountMetas[count]
		if accountMeta.IsSigner > 1 || accountMeta.IsWritable > 1 {
			return Instruction{}, SyscallErrInvalidArgument
		}

		pubkeyData, err := vm.Translate(accountMeta.PubkeyAddr, solana.PublicKeyLength, false)
		if err != nil {
			return Instruction{}, err
		}
		pubkey := solana.PublicKeyFromBytes(pubkeyData)

		var isSigner bool
		var isWritable bool
		if accountMeta.IsSigner == 1 {
			isSigner = true
		}
		if accountMeta.IsWritable == 1 {
			isWritable = true
		}

		newAccountMeta := AccountMeta{Pubkey: pubkey, IsSigner: isSigner, IsWritable: isWritable}
		accounts = append(accounts, newAccountMeta)
	}

	return Instruction{Accounts: accounts, Data: data, ProgramId: programId}, nil
}

func translateInstructionRust(vm sbpf.VM, addr uint64) (Instruction, error) {
	ixData, err := vm.Translate(addr, SolInstructionRustStructSize, false)
	if err != nil {
		return Instruction{}, err
	}

	byteReader := bytes.NewReader(ixData)
	var ix SolInstructionRust

	err = ix.Unmarshal(byteReader)
	if err != nil {
		return Instruction{}, err
	}

	err = checkInstructionSize(executionCtx(vm), ix.Accounts.Len, ix.Data.Len)
	if err != nil {
		return Instruction{}, err
	}

	accountMetasData, err := vm.Translate(ix.Accounts.Addr, AccountMetaSize*ix.Accounts.Len, false)
	if err != nil {
		return Instruction{}, err
	}

	var accountMetas []AccountMeta
	byteReader.Reset(accountMetasData)

	for i := uint64(0); i < ix.Accounts.Len; i++ {
		var accountMeta AccountMeta
		err = accountMeta.Unmarshal(byteReader)
		if err != nil {
			return Instruction{}, err
		}
		accountMetas = append(accountMetas, accountMeta)
	}

	data, err := vm.Translate(ix.Data.Addr, ix.Data.Len, false)
	if err != nil {
		return Instruction{}, err
	}

	return Instruction{Accounts: accountMetas, Data: data, ProgramId: ix.Pubkey}, nil
}

func translateSigners(vm sbpf.VM, programId solana.PublicKey, signersSeedsAddr, signersSeedsLen uint64) ([]solana.PublicKey, error) {

	if signersSeedsLen == 0 {
		return nil, nil
	}

	if signersSeedsLen > MaxSigners {
		return nil, SyscallErrTooManySigners
	}

	ssLen := safemath.SaturatingMulU64(signersSeedsLen, SolSignerSeedsCSize)
	signerSeedsMem, err := vm.Translate(signersSeedsAddr, ssLen, false)
	if err != nil {
		return nil, err
	}

	byteReader := bytes.NewReader(signerSeedsMem)
	var signerSeeds []VectorDescrC
	for count := uint64(0); count < signersSeedsLen; count++ {
		var s VectorDescrC
		err = s.Unmarshal(byteReader)
		if err != nil {
			return nil, err
		}
		signerSeeds = append(signerSeeds, s)
	}

	var pdas []solana.PublicKey

	for _, signerSeed := range signerSeeds {

		if signerSeed.Len > MaxSeeds {
			return nil, SyscallErrMaxSeedLengthExceeded
		}

		sz := safemath.SaturatingMulU64(signerSeed.Len, SolSignerSeedsCSize)
		mem, err := vm.Translate(signerSeed.Addr, sz, false)
		if err != nil {
			return nil, err
		}

		seedReader := bytes.NewReader(mem)
		var seeds []VectorDescrC

		for i := uint64(0); i < signerSeed.Len; i++ {
			var seed VectorDescrC
			err = seed.Unmarshal(seedReader)
			if err != nil {
				return nil, err
			}
			seeds = append(seeds, seed)
		}

		var seedBytes [][]byte

		for _, seed := range seeds {
			seedFragmentMem, err := vm.Translate(seed.Addr, seed.Len, false)
			if err != nil {
				return nil, err
			}
			seedBytes = append(seedBytes, seedFragmentMem)
		}

		pubkey, err := solana.CreateProgramAddress(seedBytes, programId)
		if err != nil {
			return nil, err
		}
		pdas = append(pdas, pubkey)

	}

	return pdas, nil
}

func isBpfLoaderUpgradebleUpgradeInstr(data []byte) bool {
	return len(data) != 0 && data[0] == 3
}

func isBpfLoaderUpgradebleSetAuthorityInstr(data []byte) bool {
	return len(data) != 0 && data[0] == 4
}

func isBpfLoaderUpgradebleSetAuthorityCheckedInstr(data []byte) bool {
	return len(data) != 0 && data[0] == 7
}

func isBpfLoaderUpgradebleCloseInstr(data []byte) bool {
	return len(data) != 0 && data[0] == 5
}

func isPrecompile(programId solana.PublicKey) bool {
	if programId == Secp256kPrecompileAddr || programId == Ed25519PrecompileAddr {
		return true
	} else {
		return false
	}
}

func checkAuthorizedProgram(execCtx *ExecutionCtx, programId solana.PublicKey, instructionData []byte) error {

	if programId == base58.MustDecodeFromString("NativeLoader1111111111111111111111111111111") ||
		programId == solana.BPFLoaderProgramID ||
		programId == solana.BPFLoaderDeprecatedProgramID ||
		(programId == solana.BPFLoaderUpgradeableProgramID &&
			!(isBpfLoaderUpgradebleUpgradeInstr(instructionData) ||
				isBpfLoaderUpgradebleSetAuthorityInstr(instructionData) ||
				(execCtx.GlobalCtx.Features.IsActive(features.EnableBpfLoaderSetAuthorityCheckedIx) && isBpfLoaderUpgradebleSetAuthorityCheckedInstr(instructionData)) ||
				isBpfLoaderUpgradebleCloseInstr(instructionData))) ||
		isPrecompile(programId) {
		return SyscallErrProgramNotSupported
	}

	return nil
}

func checkAccountInfos(execCtx *ExecutionCtx, numAccountInfos uint64) error {
	if execCtx.GlobalCtx.Features.IsActive(features.LoosenCpiSizeRestriction) {
		var maxAccountInfos uint64
		if execCtx.GlobalCtx.Features.IsActive(features.IncreaseTxAccountLockLimit) {
			maxAccountInfos = MaxCpiAccountInfos
		} else {
			maxAccountInfos = 64
		}
		if numAccountInfos > maxAccountInfos {
			return SyscallErrMaxInstructionAccountInfosExceeded
		}
	} else {
		adjustedLen := safemath.SaturatingMulU64(numAccountInfos, solana.PublicKeyLength)
		if adjustedLen > CUMaxCpiInstructionSize {
			return SyscallErrTooManyAccounts
		}
	}
	return nil
}

func translateAccountInfosC(vm sbpf.VM, accountInfosAddr, accountInfosLen uint64) ([]SolAccountInfoC, []solana.PublicKey, error) {
	size := safemath.SaturatingMulU64(accountInfosLen, SolAccountInfoCSize)
	accountInfosData, err := vm.Translate(accountInfosAddr, size, false)
	if err != nil {
		return nil, nil, err
	}

	var accountInfos []SolAccountInfoC
	reader := bytes.NewReader(accountInfosData)

	for count := uint64(0); count < accountInfosLen; count++ {
		var acctInfo SolAccountInfoC
		err = acctInfo.Unmarshal(reader)
		if err != nil {
			return nil, nil, err
		}
		accountInfos = append(accountInfos, acctInfo)
	}

	err = checkAccountInfos(executionCtx(vm), uint64(len(accountInfos)))
	if err != nil {
		return nil, nil, err
	}

	var accountInfoKeys []solana.PublicKey
	for _, acctInfo := range accountInfos {
		keyData, err := vm.Translate(acctInfo.KeyAddr, 32, false)
		if err != nil {
			return nil, nil, err
		}
		key := solana.PublicKeyFromBytes(keyData)
		accountInfoKeys = append(accountInfoKeys, key)
	}

	return accountInfos, accountInfoKeys, nil
}

func translateAccountInfosRust(vm sbpf.VM, accountInfosAddr, accountInfosLen uint64) ([]SolAccountInfoRust, []solana.PublicKey, error) {
	size := safemath.SaturatingMulU64(accountInfosLen, SolAccountInfoRustSize)
	accountInfosData, err := vm.Translate(accountInfosAddr, size, false)
	if err != nil {
		return nil, nil, err
	}

	var accountInfos []SolAccountInfoRust
	reader := bytes.NewReader(accountInfosData)

	for count := uint64(0); count < accountInfosLen; count++ {
		var acctInfo SolAccountInfoRust
		err = acctInfo.Unmarshal(reader)
		if err != nil {
			return nil, nil, err
		}
		accountInfos = append(accountInfos, acctInfo)
	}

	err = checkAccountInfos(executionCtx(vm), uint64(len(accountInfos)))
	if err != nil {
		return nil, nil, err
	}

	var accountInfoKeys []solana.PublicKey
	for _, acctInfo := range accountInfos {
		keyData, err := vm.Translate(acctInfo.PubkeyAddr, 32, false)
		if err != nil {
			return nil, nil, err
		}
		key := solana.PublicKeyFromBytes(keyData)
		accountInfoKeys = append(accountInfoKeys, key)
	}

	return accountInfos, accountInfoKeys, nil
}

type callerAccountsAndIndex struct {
	index   uint64
	account CallerAccount
}

func callerAccountFromAccountInfoC(vm sbpf.VM, execCtx *ExecutionCtx, accountInfo SolAccountInfoC) (CallerAccount, error) {

	var callerAcct CallerAccount

	lamports, err := vm.Read64(accountInfo.LamportsAddr)
	if err != nil {
		return callerAcct, err
	}
	callerAcct.Lamports = lamports

	accOwner, err := vm.Translate(accountInfo.OwnerAddr, solana.PublicKeyLength, false)
	if err != nil {
		return callerAcct, err
	}
	callerAcct.Owner = solana.PublicKeyFromBytes(accOwner)

	cost := accountInfo.DataLen / CUCpiBytesPerUnit
	err = execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return callerAcct, err
	}

	acctData, err := vm.Translate(accountInfo.DataAddr, accountInfo.DataLen, false)
	if err != nil {
		return callerAcct, err
	}

	callerAcct.SerializedData = &acctData
	callerAcct.SerializedDataLen = accountInfo.DataLen
	callerAcct.Executable = accountInfo.Executable
	callerAcct.RentEpoch = accountInfo.RentEpoch

	return callerAcct, nil
}

func callerAccountFromAccountInfoRust(vm sbpf.VM, execCtx *ExecutionCtx, accountInfo SolAccountInfoRust) (CallerAccount, error) {

	var callerAcct CallerAccount

	lamportsBoxData, err := vm.Translate(accountInfo.LamportsBoxAddr, RefCellRustSize, false)
	if err != nil {
		return callerAcct, err
	}

	reader := bytes.NewReader(lamportsBoxData)

	var lamportsBox RefCellRust
	err = lamportsBox.Unmarshal(reader)
	if err != nil {
		return callerAcct, err
	}

	lamports, err := vm.Read64(lamportsBox.Addr)
	if err != nil {
		return callerAcct, err
	}
	callerAcct.Lamports = lamports

	ownerAddrBytes, err := vm.Translate(accountInfo.OwnerAddr, solana.PublicKeyLength, false)
	if err != nil {
		return callerAcct, err
	}
	callerAcct.Owner = solana.PublicKeyFromBytes(ownerAddrBytes)

	dataBoxBytes, err := vm.Translate(accountInfo.DataBoxAddr, RefCellRustSize, false)
	if err != nil {
		return callerAcct, err
	}

	reader.Reset(dataBoxBytes)

	var dataBox RefCellVecRust
	err = dataBox.Unmarshal(reader)
	if err != nil {
		return callerAcct, err
	}

	cost := dataBox.Len / CUCpiBytesPerUnit
	err = execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return callerAcct, err
	}

	data, err := vm.Translate(dataBox.Addr, dataBox.Len, false)
	if err != nil {
		return callerAcct, err
	}

	callerAcct.SerializedData = &data
	callerAcct.SerializedDataLen = dataBox.Len
	callerAcct.Executable = accountInfo.Executable == 1
	callerAcct.RentEpoch = accountInfo.RentEpoch

	return callerAcct, nil
}

func updateCalleeAccount(execCtx *ExecutionCtx, callerAccount CallerAccount, calleeAccount *BorrowedAccount) error {
	if calleeAccount.Account.Lamports != callerAccount.Lamports {
		calleeAccount.Account.Lamports = callerAccount.Lamports
	}

	err1 := calleeAccount.CanDataBeResized(callerAccount.SerializedDataLen)
	err2 := calleeAccount.DataCanBeChanged(execCtx.GlobalCtx.Features)

	var err error

	if err1 != nil {
		err = err1
	} else if err2 != nil {
		err = err2
	}

	// can't change data
	if err != nil {
		if !bytes.Equal(*callerAccount.SerializedData, calleeAccount.Data()) {
			return err
		}

		// can't change data, but data didn't actually change anyway
		return nil
	}

	err = calleeAccount.SetData(execCtx.GlobalCtx.Features, *callerAccount.SerializedData)
	if err != nil {
		return err
	}

	if calleeAccount.Owner() != callerAccount.Owner {
		err = calleeAccount.SetOwner(execCtx.GlobalCtx.Features, callerAccount.Owner)
	}

	return err
}

func updateCallerAccount(vm sbpf.VM, callerAcct *CallerAccount, calleeAcct *BorrowedAccount) error {

	callerAcct.Lamports = calleeAcct.Lamports()
	callerAcct.Owner = calleeAcct.Owner()

	prevLen := callerAcct.RefToLenInVm
	postLen := uint64(len(calleeAcct.Data()))

	if prevLen != postLen {
		// TODO: use constant
		maxPermittedIncrease := uint64(10240)

		// account data size increased by too much
		if postLen > safemath.SaturatingAddU64(callerAcct.SerializedDataLen, maxPermittedIncrease) {
			return InstrErrInvalidRealloc
		}

		if postLen < prevLen {
			serializedData := *callerAcct.SerializedData
			if uint64(len(serializedData)) < postLen {
				return InstrErrAccountDataTooSmall
			}
			for i := range serializedData[postLen:] {
				serializedData[i] = 0
			}
		}

		sd, err := vm.Translate(callerAcct.VmDataAddr, postLen, false)
		if err != nil {
			return err
		}
		callerAcct.SerializedData = &sd
		callerAcct.RefToLenInVm = postLen

		ptrAddr := safemath.SaturatingSubU64(callerAcct.VmDataAddr, 8)
		serializedLenSlice, err := vm.Translate(ptrAddr, 8, false)
		if err != nil {
			return err
		}
		binary.LittleEndian.PutUint64(serializedLenSlice, postLen)
	}

	toSlice := *callerAcct.SerializedData
	fromSlice := calleeAcct.Data()

	if uint64(len(fromSlice)) < postLen {
		return SyscallErrInvalidLength
	}

	fromSlice = fromSlice[:postLen]

	if len(toSlice) != len(fromSlice) {
		return InstrErrAccountDataTooSmall
	}

	copy(toSlice, fromSlice)

	return nil
}

func translateAndUpdateAccountsC(vm sbpf.VM, instructionAccts []InstructionAccount, programIndices []uint64, accountInfoKeys []solana.PublicKey, accountInfos []SolAccountInfoC, accountInfosAddr uint64, isLoaderDeprecated bool) (TranslatedAccounts, error) {
	execCtx := executionCtx(vm)
	txCtx := execCtx.TransactionContext

	ixCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return nil, err
	}

	accounts := make(TranslatedAccounts, len(instructionAccts)+1)

	idx := len(programIndices) - 1
	if idx < 0 {
		return nil, InstrErrMissingAccount
	}
	programAcctIdx := programIndices[idx]
	accounts = append(accounts, TranslatedAccount{IndexOfAccount: programAcctIdx, CallerAccount: nil})

	for instructionAcctIdx, instructionAcct := range instructionAccts {
		if uint64(instructionAcctIdx) != instructionAcct.IndexInCallee {
			continue
		}
		calleeAcct, err := ixCtx.BorrowInstructionAccount(txCtx, instructionAcct.IndexInCaller)
		if err != nil {
			return nil, err
		}

		accountKey, err := txCtx.KeyOfAccountAtIndex(instructionAcct.IndexInTransaction)
		if err != nil {
			return nil, err
		}

		if calleeAcct.IsExecutable() {
			cost := uint64(len(calleeAcct.Data()) / CUCpiBytesPerUnit)
			err = execCtx.ComputeMeter.Consume(cost)
			if err != nil {
				return nil, InstrErrComputationalBudgetExceeded
			}
		} else {
			var found bool
			for index, accountInfoKey := range accountInfoKeys {
				if accountKey == accountInfoKey {
					accountInfo := accountInfos[index]
					callerAcct, err := callerAccountFromAccountInfoC(vm, execCtx, accountInfo)
					if err != nil {
						return nil, err
					}
					err = updateCalleeAccount(execCtx, callerAcct, calleeAcct)
					if err != nil {
						return nil, err
					}

					var c *CallerAccount
					if instructionAcct.IsWritable {
						c = &callerAcct
					} else {
						c = nil
					}
					accounts = append(accounts, TranslatedAccount{IndexOfAccount: instructionAcct.IndexInCaller, CallerAccount: c})
					found = true
				}
			}
			if !found {
				return nil, InstrErrMissingAccount
			}
		}
	}

	return accounts, nil
}

func translateAndUpdateAccountsRust(vm sbpf.VM, instructionAccts []InstructionAccount, programIndices []uint64, accountInfoKeys []solana.PublicKey, accountInfos []SolAccountInfoRust, accountInfosAddr uint64, isLoaderDeprecated bool) (TranslatedAccounts, error) {
	execCtx := executionCtx(vm)
	txCtx := execCtx.TransactionContext

	ixCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return nil, err
	}

	accounts := make(TranslatedAccounts, len(instructionAccts)+1)

	idx := len(programIndices) - 1
	if idx < 0 {
		return nil, InstrErrMissingAccount
	}
	programAcctIdx := programIndices[idx]
	accounts = append(accounts, TranslatedAccount{IndexOfAccount: programAcctIdx, CallerAccount: nil})

	for instructionAcctIdx, instructionAcct := range instructionAccts {
		if uint64(instructionAcctIdx) != instructionAcct.IndexInCallee {
			continue
		}
		calleeAcct, err := ixCtx.BorrowInstructionAccount(txCtx, instructionAcct.IndexInCaller)
		if err != nil {
			return nil, err
		}

		accountKey, err := txCtx.KeyOfAccountAtIndex(instructionAcct.IndexInTransaction)
		if err != nil {
			return nil, err
		}

		if calleeAcct.IsExecutable() {
			cost := uint64(len(calleeAcct.Data()) / CUCpiBytesPerUnit)
			err = execCtx.ComputeMeter.Consume(cost)
			if err != nil {
				return nil, InstrErrComputationalBudgetExceeded
			}
		} else {
			var found bool
			for index, accountInfoKey := range accountInfoKeys {
				if accountKey == accountInfoKey {
					accountInfo := accountInfos[index]
					callerAcct, err := callerAccountFromAccountInfoRust(vm, execCtx, accountInfo)
					if err != nil {
						return nil, err
					}
					err = updateCalleeAccount(execCtx, callerAcct, calleeAcct)
					if err != nil {
						return nil, err
					}

					var c *CallerAccount
					if instructionAcct.IsWritable {
						c = &callerAcct
					} else {
						c = nil
					}
					accounts = append(accounts, TranslatedAccount{IndexOfAccount: instructionAcct.IndexInCaller, CallerAccount: c})
					found = true
				}
			}
			if !found {
				return nil, InstrErrMissingAccount
			}
		}
	}

	return accounts, nil
}

func translateAccountsC(vm sbpf.VM, instructionAccts []InstructionAccount, programIndices []uint64, accountInfosAddr uint64, accountInfosLen uint64, isLoaderDeprecated bool) (TranslatedAccounts, error) {

	accountInfos, accountInfoKeys, err := translateAccountInfosC(vm, accountInfosAddr, accountInfosLen)
	if err != nil {
		return nil, err
	}

	return translateAndUpdateAccountsC(vm, instructionAccts, programIndices, accountInfoKeys, accountInfos, accountInfosAddr, isLoaderDeprecated)
}

func translateAccountsRust(vm sbpf.VM, instructionAccts []InstructionAccount, programIndices []uint64, accountInfosAddr uint64, accountInfosLen uint64, isLoaderDeprecated bool) (TranslatedAccounts, error) {

	accountInfos, accountInfoKeys, err := translateAccountInfosRust(vm, accountInfosAddr, accountInfosLen)
	if err != nil {
		return nil, err
	}

	return translateAndUpdateAccountsRust(vm, instructionAccts, programIndices, accountInfoKeys, accountInfos, accountInfosAddr, isLoaderDeprecated)
}

// SyscallInvokeSignedCImpl is an implementation of the sol_invoke_signed_c syscall
func SyscallInvokeSignedCImpl(vm sbpf.VM, instructionAddr, accountInfosAddr, accountInfosLen, signerSeedsAddr, signerSeedsLen uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = execCtx.ComputeMeter.Consume(CUInvokeUnits)
	if err != nil {
		return
	}

	// translate instruction
	ix, err := translateInstructionC(vm, instructionAddr)
	if err != nil {
		return
	}

	txCtx := transactionCtx(vm)
	instructionCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return
	}

	callerProgramId, err := instructionCtx.LastProgramKey(txCtx)

	// translate signers
	signers, err := translateSigners(vm, callerProgramId, signerSeedsAddr, signerSeedsAddr)

	fmt.Printf("got C ABI CPI call from programId: %s -----> %s, %d signers\n", callerProgramId, ix.ProgramId, len(signers))

	var isLoaderDeprecated bool
	lastProgramAcct, err := instructionCtx.BorrowLastProgramAccount(txCtx)
	if err != nil {
		r0 = 1
		return
	}
	if lastProgramAcct.Owner() == BpfLoaderDeprecatedAddr {
		isLoaderDeprecated = true
	}
	lastProgramAcct.Drop()

	instructionAccts, programIndices, err := execCtx.PrepareInstruction(ix, signers)
	if err != nil {
		r0 = 1
		return
	}

	err = checkAuthorizedProgram(execCtx, ix.ProgramId, ix.Data)
	if err != nil {
		r0 = 1
		return
	}

	accounts, err := translateAccountsC(vm, instructionAccts, programIndices, accountInfosAddr, accountInfosLen, isLoaderDeprecated)
	if err != nil {
		r0 = 1
		return
	}

	err = execCtx.ProcessInstruction(ix.Data, instructionAccts, programIndices)
	if err != nil {
		r0 = uint64(translateErrToInstrErrCode(err))
		return
	}

	for _, acct := range accounts {
		var calleeAcct *BorrowedAccount
		calleeAcct, err = instructionCtx.BorrowInstructionAccount(txCtx, acct.IndexOfAccount)
		if err != nil {
			return
		}
		err = updateCallerAccount(vm, acct.CallerAccount, calleeAcct)
		if err != nil {
			return
		}
	}

	r0 = 0
	return
}

//var SyscallInvokeSignedC = sbpf.SyscallFunc5(SyscallInvokeSignedCImpl)

// SyscallInvokeSignedRustImpl is an implementation of the sol_invoke_signed_rust syscall
func SyscallInvokeSignedRustImpl(vm sbpf.VM, instructionAddr, accountInfosAddr, accountInfosLen, signerSeedsAddr, signerSeedsLen uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = execCtx.ComputeMeter.Consume(CUInvokeUnits)
	if err != nil {
		return
	}

	// translate instruction
	ix, err := translateInstructionRust(vm, instructionAddr)
	if err != nil {
		return
	}

	txCtx := transactionCtx(vm)
	instructionCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return
	}

	callerProgramId, err := instructionCtx.LastProgramKey(txCtx)

	// translate signers
	signers, err := translateSigners(vm, callerProgramId, signerSeedsAddr, signerSeedsAddr)

	fmt.Printf("got Rust ABI CPI call from programId: %s -----> %s, %d signers\n", callerProgramId, ix.ProgramId, len(signers))

	var isLoaderDeprecated bool
	lastProgramAcct, err := instructionCtx.BorrowLastProgramAccount(txCtx)
	if err != nil {
		r0 = 1
		return
	}
	if lastProgramAcct.Owner() == BpfLoaderDeprecatedAddr {
		isLoaderDeprecated = true
	}
	lastProgramAcct.Drop()

	instructionAccts, programIndices, err := execCtx.PrepareInstruction(ix, signers)
	if err != nil {
		r0 = 1
		return
	}

	err = checkAuthorizedProgram(execCtx, ix.ProgramId, ix.Data)
	if err != nil {
		r0 = 1
		return
	}

	accounts, err := translateAccountsRust(vm, instructionAccts, programIndices, accountInfosAddr, accountInfosLen, isLoaderDeprecated)
	if err != nil {
		r0 = 1
		return
	}

	err = execCtx.ProcessInstruction(ix.Data, instructionAccts, programIndices)
	if err != nil {
		r0 = uint64(translateErrToInstrErrCode(err))
		return
	}

	for _, acct := range accounts {
		var calleeAcct *BorrowedAccount
		calleeAcct, err = instructionCtx.BorrowInstructionAccount(txCtx, acct.IndexOfAccount)
		if err != nil {
			return
		}
		err = updateCallerAccount(vm, acct.CallerAccount, calleeAcct)
		if err != nil {
			return
		}
	}

	r0 = 0
	return
}

//var SyscallInvokeSignedRust = sbpf.SyscallFunc5(SyscallInvokeSignedRustImpl)
