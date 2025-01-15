package sealevel

import (
	"encoding/binary"

	"github.com/Overclock-Validator/mithril/pkg/safemath"
	"github.com/Overclock-Validator/mithril/pkg/sbpf"
	"github.com/Overclock-Validator/mithril/pkg/util"
	"k8s.io/klog/v2"
)

func MemOpConsume(execCtx *ExecutionCtx, n uint64) error {
	cost := max(CUMemOpBaseCost, n/CUCpiBytesPerUnit)
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
func SyscallMemcpyImpl(vm sbpf.VM, dst, src, n uint64) (uint64, error) {
	klog.Infof("SyscallMemcpy")

	execCtx := executionCtx(vm)
	err := MemOpConsume(execCtx, n)
	if err != nil {
		return syscallErr(err)
	}

	// memcpy when src and dst are overlapping results in undefined behaviour,
	// hence check if there is an overlap and return early with an error if so.
	if !isNonOverlapping(src, n, dst, n) {
		return syscallErr(SyscallErrCopyOverlapping)
	}

	if n == 0 {
		return syscallSuccess(0)
	}

	err = memmoveImplInternal(vm, dst, src, n)
	if err != nil {
		return syscallErr(err)
	} else {
		return syscallSuccess(0)
	}
}

var SyscallMemcpy = sbpf.SyscallFunc3(SyscallMemcpyImpl)

// SyscallMemmoveImpl is the implementation for the memmove (sol_memmove_) syscall.
func SyscallMemmoveImpl(vm sbpf.VM, dst, src, n uint64) (uint64, error) {
	klog.Infof("SyscallMemmove")

	execCtx := executionCtx(vm)
	err := MemOpConsume(execCtx, n)
	if err != nil {
		return syscallCuErr()
	}

	err = memmoveImplInternal(vm, dst, src, n)
	if err != nil {
		return syscallErr(err)
	} else {
		return syscallSuccess(0)
	}
}

var SyscallMemmove = sbpf.SyscallFunc3(SyscallMemmoveImpl)

// SyscallMemcmpImpl is the implementation for the memcmp (sol_memcmp_) syscall.
func SyscallMemcmpImpl(vm sbpf.VM, addr1, addr2, n, resultAddr uint64) (uint64, error) {
	klog.Infof("SyscallMemcmp")

	execCtx := executionCtx(vm)
	err := MemOpConsume(execCtx, n)
	if err != nil {
		return syscallCuErr()
	}

	slice1, err := vm.Translate(addr1, n, false)
	if err != nil {
		return syscallErr(err)
	}

	slice2, err := vm.Translate(addr2, n, false)
	if err != nil {
		return syscallErr(err)
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

	resultSlice, err := vm.Translate(resultAddr, 4, true)
	if err != nil {
		return syscallErr(err)
	}

	binary.LittleEndian.PutUint32(resultSlice, uint32(cmpResult))

	return syscallSuccess(0)
}

var SyscallMemcmp = sbpf.SyscallFunc4(SyscallMemcmpImpl)

// SyscallMemcmpImpl is the implementation for the memset (sol_memset_) syscall.
func SyscallMemsetImpl(vm sbpf.VM, dst, c, n uint64) (uint64, error) {
	klog.Infof("SyscallMemset")

	execCtx := executionCtx(vm)
	err := MemOpConsume(execCtx, n)
	if err != nil {
		return syscallCuErr()
	}

	mem, err := vm.Translate(dst, n, true)
	if err != nil {
		return syscallErr(err)
	}

	for i := uint64(0); i < n; i++ {
		mem[i] = byte(c)
	}

	return syscallSuccess(0)
}

var SyscallMemset = sbpf.SyscallFunc3(SyscallMemsetImpl)

// SyscallMemcmpImpl is the implementation for the memset (sol_memset_) syscall.
func SyscallAllocFreeImpl(vm sbpf.VM, size, freeAddr uint64) (uint64, error) {
	klog.Infof("SyscallAllocFreeImpl")

	execCtx := executionCtx(vm)

	// this is a free() call, but this is a bump allocator, so do nothing
	if freeAddr != 0 {
		return syscallSuccess(0)
	}

	var align uint64
	if execCtx.CheckAligned() {
		align = 8
	} else {
		align = 1
	}

	heapSize := util.AlignUp(vm.HeapSize(), align)
	heapAddr := safemath.SaturatingAddU64(heapSize, sbpf.VaddrHeap)
	heapSize = safemath.SaturatingAddU64(heapSize, size)

	if heapSize > vm.HeapMax() {
		return syscallSuccess(0)
	}

	vm.UpdateHeapSize(heapSize)

	return syscallSuccess(heapAddr)
}

var SyscallAllocFree = sbpf.SyscallFunc2(SyscallAllocFreeImpl)
