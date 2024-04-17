package sealevel

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/safemath"
	"go.firedancer.io/radiance/pkg/sbpf"
	"go.firedancer.io/radiance/pkg/sbpf/cu"
)

const MaxSigners = 16

func translateInstructionC(vm sbpf.VM, addr uint64, cu *int) (Instruction, error) {
	ixData, err := vm.Translate(addr, SolInstructionStructSize, false)
	if err != nil {
		return Instruction{}, err
	}

	byteReader := bytes.NewReader(ixData)
	var ix SolInstruction

	err = ix.Unmarshal(byteReader)
	if err != nil {
		return Instruction{}, err
	}

	// TODO: implement an `check_instruction_size()` upon ix

	pkData, err := vm.Translate(ix.programIdAddr, solana.PublicKeyLength, false)
	if err != nil {
		return Instruction{}, err
	}
	programId := solana.PublicKeyFromBytes(pkData)

	accountMetasData, err := vm.Translate(ix.accountsAddr, AccountMetaSize*ix.accountsLen, false)
	if err != nil {
		return Instruction{}, err
	}

	byteReader.Reset(accountMetasData)

	var accountMetas []SolAccountMeta

	for count := uint64(0); count < ix.accountsLen; count++ {
		var am SolAccountMeta
		err = am.Unmarshal(byteReader)
		if err != nil {
			return Instruction{}, err
		}
		accountMetas = append(accountMetas, am)
	}

	// TODO: do CU accounting for `loosen_cpi_size_restriction` feature gate

	data, err := vm.Translate(ix.dataAddr, ix.dataLen, false)

	accounts := make([]AccountMeta, ix.accountsLen)
	for count := uint64(0); count < ix.accountsLen; count++ {
		accountMeta := accountMetas[count]
		if accountMeta.IsSigner > 1 || accountMeta.IsWritable > 1 {
			return Instruction{}, InvalidArgument
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

func translateSigners(vm sbpf.VM, programId solana.PublicKey, signersSeedsAddr, signersSeedsLen uint64) ([]solana.PublicKey, error) {

	if signersSeedsLen == 0 {
		return nil, nil
	}

	if signersSeedsLen > MaxSigners {
		return nil, TooManySigners
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
			return nil, MaxSeedLengthExceeded
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

// TODO: implement
func checkAuthorizedProgram(programId solana.PublicKey, instructionData []byte, execCtx *ExecutionCtx) error {
	return nil
}

// TODO: implement
func checkAccountInfos(numAccountInfos uint64, execCtx *ExecutionCtx) error {
	return nil
}

func translateAccountInfosC(vm sbpf.VM, accountInfosAddr, accountInfosLen uint64, execCtx *ExecutionCtx) ([]SolAccountInfo, []solana.PublicKey, error) {
	size := safemath.SaturatingMulU64(accountInfosLen, SolAccountInfoSize)
	accountInfosData, err := vm.Translate(accountInfosAddr, size, false)
	if err != nil {
		return nil, nil, err
	}

	var accountInfos []SolAccountInfo
	reader := bytes.NewReader(accountInfosData)

	for count := uint64(0); count < accountInfosLen; count++ {
		var acctInfo SolAccountInfo
		err = acctInfo.Unmarshal(reader)
		if err != nil {
			return nil, nil, err
		}
		accountInfos = append(accountInfos, acctInfo)
	}

	err = checkAccountInfos(uint64(len(accountInfos)), execCtx)
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

type callerAccountsAndIndex struct {
	index   uint64
	account CallerAccount
}

func callerAccountFromAccountInfoC(vm sbpf.VM, execCtx *ExecutionCtx, accountInfo SolAccountInfo) (CallerAccount, error) {

	// TODO: logic for 'direct mapping' feature gate

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

	cost := int(accountInfo.DataLen / CUCpiBytesPerUnit)
	execCtx.ComputeMeter, err = cu.ConsumeComputeMeter(execCtx.ComputeMeter, cost)
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

func updateCallerAccount(vm sbpf.VM, execCtx *ExecutionCtx, callerAcct *CallerAccount, calleeAcct *BorrowedAccount) error {

	callerAcct.Lamports = calleeAcct.Lamports()
	callerAcct.Owner = calleeAcct.Owner()

	prevLen := callerAcct.RefToLenInVm
	postLen := uint64(len(calleeAcct.Data()))

	if prevLen != postLen {
		// TODO: use constant
		maxPermittedIncrease := uint64(10240)

		// account data size increased by too much
		if postLen > safemath.SaturatingAddU64(callerAcct.SerializedDataLen, maxPermittedIncrease) {
			return ErrInvalidRealloc
		}

		if postLen < prevLen {
			serializedData := *callerAcct.SerializedData
			if uint64(len(serializedData)) < postLen {
				return ErrAccountDataTooSmall
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
		return InvalidLength
	}

	fromSlice = fromSlice[:postLen]

	if len(toSlice) != len(fromSlice) {
		return ErrAccountDataTooSmall
	}

	copy(toSlice, fromSlice)

	return nil
}

func translateAndUpdateAccountsC(vm sbpf.VM, instructionAccts []InstructionAccount, programIndices []uint64, accountInfoKeys []solana.PublicKey, accountInfos []SolAccountInfo, accountInfosAddr uint64, isLoaderDeprecated bool, execCtx *ExecutionCtx) (TranslatedAccounts, error) {
	txCtx := execCtx.TransactionContext

	ixCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return nil, err
	}

	accounts := make(TranslatedAccounts, len(instructionAccts)+1)

	idx := len(programIndices) - 1
	if idx < 0 {
		return nil, ErrMissingAccount
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

		if calleeAcct.IsExecutable(execCtx.GlobalCtx.Features) {
			cost := len(calleeAcct.Data()) / CUCpiBytesPerUnit
			execCtx.ComputeMeter, err = cu.ConsumeComputeMeter(execCtx.ComputeMeter, cost)
			if err != nil {
				return nil, ErrComputationalBudgetExceeded
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
				return nil, ErrMissingAccount
			}
		}
	}

	return accounts, nil
}

func translateAccountsC(vm sbpf.VM, instructionAccts []InstructionAccount, programIndices []uint64, accountInfosAddr uint64, accountInfosLen uint64, isLoaderDeprecated bool, execCtx *ExecutionCtx) (TranslatedAccounts, error) {

	accountInfos, accountInfoKeys, err := translateAccountInfosC(vm, accountInfosAddr, accountInfosLen, execCtx)
	if err != nil {
		return nil, err
	}

	return translateAndUpdateAccountsC(vm, instructionAccts, programIndices, accountInfoKeys, accountInfos, accountInfosAddr, isLoaderDeprecated, execCtx)
}

// SyscallInvokeSignedCImpl is an implementation of the sol_invoke_signed_c syscall
func SyscallInvokeSignedCImpl(vm sbpf.VM, instructionAddr, accountInfosAddr, accountInfosLen, signerSeedsAddr, signerSeedsLen uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	cuOut, err = cu.ConsumeComputeMeter(cuIn, CUInvokeUnits)
	if err != nil {
		return
	}

	// translate instruction
	ix, err := translateInstructionC(vm, instructionAddr, &cuIn)
	if err != nil {
		return
	}

	txCtx := transactionCtx(vm)
	execCtx := executionCtx(vm)
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

	instructionAccts, programIndices, err := execCtx.PrepareInstruction(ix, signers)
	if err != nil {
		r0 = 1
		return
	}

	err = checkAuthorizedProgram(ix.ProgramId, ix.Data, execCtx)
	if err != nil {
		r0 = 1
		return
	}

	accounts, err := translateAccountsC(vm, instructionAccts, programIndices, accountInfosAddr, accountInfosLen, isLoaderDeprecated, execCtx)
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
		err = updateCallerAccount(vm, execCtx, acct.CallerAccount, calleeAcct)
		if err != nil {
			return
		}
	}

	r0 = 0
	return
}

var SyscallInvokeSignedC = sbpf.SyscallFunc5(SyscallInvokeSignedCImpl)
