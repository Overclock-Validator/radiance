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

// SyscallGetReturnDataImpl is an implementation of the sol_get_return_data syscall
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

const MaxReturnData = 1024

// SyscallSetReturnDataImpl is an implementation of the sol_set_return_data syscall
func SyscallSetReturnDataImpl(vm sbpf.VM, addr, length uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	cost := safemath.SaturatingAddU64(length/CUCpiBytesPerUnit, CUSyscallBaseCost)
	cuOut, err = cu.ConsumeComputeMeter(cuIn, int(cost))
	if err != nil {
		return
	}

	if length > MaxReturnData {
		err = ReturnDataTooLarge
		return
	}

	var returnData []byte
	if length == 0 {
		returnData = make([]byte, 0)
	} else {
		returnData, err = vm.Translate(addr, length, false)
		if err != nil {
			return
		}
	}

	txCtx := transactionCtx(vm)
	programId := txCtx.CurrentInstructionCtx().ProgramId()
	txCtx.SetReturnData(programId, returnData)

	r0 = 0
	return
}

var SyscallSetReturnData = sbpf.SyscallFunc2(SyscallSetReturnDataImpl)
