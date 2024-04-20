package sealevel

import (
	"go.firedancer.io/radiance/pkg/sbpf"
)

func MemOpConsume(execCtx *ExecutionCtx, n uint64) error {
	perBytesCost := n / CUCpiBytesPerUnit
	var cost uint64
	if CUMemOpBaseCost > perBytesCost {
		cost = CUMemOpBaseCost
	} else {
		cost = perBytesCost
	}
	return execCtx.ComputeMeter.Consume(cost)
}

func memmoveImplInternal(vm sbpf.VM, dst, src, n uint64) (err error) {
	srcBuf := make([]byte, n)
	err = vm.Read(src, srcBuf)
	if err != nil {
		return
	}
	err = vm.Write(dst, srcBuf)
	return
}

// SyscallMemcpyImpl is the implementation of the memcpy (sol_memcpy_) syscall.
// Overlapping src and dst for a given n bytes to be copied results in an error being returned.
func SyscallMemcpyImpl(vm sbpf.VM, dst, src, n uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = MemOpConsume(execCtx, n)
	if err != nil {
		return
	}

	// memcpy when src and dst are overlapping results in undefined behaviour,
	// hence check if there is an overlap and return early with an error if so.
	if !isNonOverlapping(src, n, dst, n) {
		return r0, SyscallErrCopyOverlapping
	}

	err = memmoveImplInternal(vm, dst, src, n)
	return
}

var SyscallMemcpy = sbpf.SyscallFunc3(SyscallMemcpyImpl)

// SyscallMemmoveImpl is the implementation for the memmove (sol_memmove_) syscall.
func SyscallMemmoveImpl(vm sbpf.VM, dst, src, n uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = MemOpConsume(execCtx, n)
	if err != nil {
		return
	}

	err = memmoveImplInternal(vm, dst, src, n)
	return
}

var SyscallMemmove = sbpf.SyscallFunc3(SyscallMemmoveImpl)

// SyscallMemcmpImpl is the implementation for the memcmp (sol_memcmp_) syscall.
func SyscallMemcmpImpl(vm sbpf.VM, addr1, addr2, n, resultAddr uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = MemOpConsume(execCtx, n)
	if err != nil {
		return
	}

	slice1, err := vm.Translate(addr1, n, false)
	if err != nil {
		return
	}

	slice2, err := vm.Translate(addr2, n, false)
	if err != nil {
		return
	}

	cmpResult := int32(0)
	for count := uint64(0); count < n; count++ {
		b1 := slice1[count]
		b2 := slice2[count]
		if b1 != b2 {
			cmpResult = int32(b1) - int32(b2)
			break
		}
	}
	err = vm.Write32(resultAddr, uint32(cmpResult))
	return
}

var SyscallMemcmp = sbpf.SyscallFunc4(SyscallMemcmpImpl)

// SyscallMemcmpImpl is the implementation for the memset (sol_memset_) syscall.
func SyscallMemsetImpl(vm sbpf.VM, dst, c, n uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = MemOpConsume(execCtx, n)
	if err != nil {
		return
	}

	mem, err := vm.Translate(dst, n, true)
	if err != nil {
		return
	}

	for i := uint64(0); i < n; i++ {
		mem[i] = byte(c)
	}

	return
}

var SyscallMemset = sbpf.SyscallFunc3(SyscallMemsetImpl)
