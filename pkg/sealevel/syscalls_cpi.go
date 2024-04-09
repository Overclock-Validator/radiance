package sealevel

import (
	"bytes"
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

		newAccountMeta := AccountMeta{pubkey: pubkey, IsSigner: isSigner, IsWritable: isWritable}
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
	instructionCtx := txCtx.CurrentInstructionCtx()

	callerProgramId, err := instructionCtx.LastProgramKey(*txCtx)

	// translate signers
	signers, err := translateSigners(vm, callerProgramId, signerSeedsAddr, signerSeedsAddr)

	fmt.Printf("got C ABI CPI call from programId: %s -----> %s, %d signers\n", callerProgramId, ix.ProgramId, len(signers))

	return
}

var SyscallInvokeSignedC = sbpf.SyscallFunc5(SyscallInvokeSignedCImpl)
