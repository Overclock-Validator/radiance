package sealevel

import (
	"go.firedancer.io/radiance/pkg/safemath"
	"go.firedancer.io/radiance/pkg/sbpf"
	"go.firedancer.io/radiance/pkg/sbpf/cu"
	"go.firedancer.io/radiance/pkg/solana"
)

// SyscallGetStackHeightImpl is an implementation of the sol_get_stack_height syscall
func SyscallGetStackHeightImpl(vm sbpf.VM, cuIn int) (r0 uint64, cuOut int, err error) {
	cuOut, err = cu.ConsumeComputeMeter(cuIn, CUSyscallBaseCost)
	if err != nil {
		return
	}

	r0 = transactionCtx(vm).InstructionCtxStackHeight()
	return
}

var SyscallGetStackHeight = sbpf.SyscallFunc0(SyscallGetStackHeightImpl)

// SyscallGetStackHeightImpl is an implementation of the sol_get_stack_height syscall
func SyscallGetReturnDataImpl(vm sbpf.VM, returnDataAddr, length, programIdAddr uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	cuOut, err = cu.ConsumeComputeMeter(cuIn, CUSyscallBaseCost)
	if err != nil {
		return
	}

	programId, returnData := transactionCtx(vm).GetReturnData()

	if length > uint64(len(returnData)) {
		length = uint64(len(returnData))
	}

	if length != 0 {
		result := safemath.SaturatingAddU64(length, solana.PublicKeyLength) / CUCpiBytesPerUnit
		cuOut, err = cu.ConsumeComputeMeter(cuOut, int(result))
		if err != nil {
			return
		}

		var returnDataResult []byte
		returnDataResult, err = vm.Translate(returnDataAddr, length, true)
		if err != nil {
			return
		}

		if len(returnData) != len(returnDataResult) {
			err = InvalidLength
			return
		}

		copy(returnDataResult, returnData)

		var programIdResult []byte
		programIdResult, err = vm.Translate(programIdAddr, solana.PublicKeyLength, true)
		if err != nil {
			return
		}

		if !isNonOverlapping(returnDataAddr, length, programIdAddr, solana.PublicKeyLength) {
			err = ErrCopyOverlapping
			return
		}

		copy(programIdResult, programId[:])
	}

	r0 = uint64(len(returnData))
	return
}

var SyscallGetReturnData = sbpf.SyscallFunc3(SyscallGetReturnDataImpl)
