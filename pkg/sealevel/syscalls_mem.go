package sealevel

import (
	"errors"

	"go.firedancer.io/radiance/pkg/sbpf"
	"go.firedancer.io/radiance/pkg/sbpf/cu"
)

var (
	ErrCopyOverlapping = errors.New("Overlapping copy")
)

func MemOpConsume(cuIn int, n uint64) int {
	perBytesCost := n / CuCpiBytesPerUnit
	return cu.ConsumeLowerBound(cuIn, CUMemOpBaseCost, int(perBytesCost))
}

func isNonOverlapping(src, dst, n uint64) bool {
	if src > dst {
		return src-dst >= n
	} else {
		return dst-src >= n
	}
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
func SyscallMemcpyImpl(vm sbpf.VM, dst, src, n uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	cuOut = MemOpConsume(cuIn, n)
	if cuOut < 0 {
		return
	}

	// memcpy when src and dst are overlapping results in undefined behaviour,
	// hence check if there is an overlap and return early with an error if so.
	if !isNonOverlapping(src, dst, n) {
		return r0, cuOut, ErrCopyOverlapping
	}

	err = memmoveImplInternal(vm, dst, src, n)
	return
}

var SyscallMemcpy = sbpf.SyscallFunc3(SyscallMemcpyImpl)

// SyscallMemmoveImpl is the implementation for the memmove (sol_memmove_) syscall.
func SyscallMemmoveImpl(vm sbpf.VM, dst, src, n uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	cuOut = MemOpConsume(cuIn, n)
	if cuOut < 0 {
		return
	}
	err = memmoveImplInternal(vm, dst, src, n)
	return
}

var SyscallMemmove = sbpf.SyscallFunc3(SyscallMemmoveImpl)

// SyscallMemcmpImpl is the implementation for the memcmp (sol_memcmp_) syscall.
func SyscallMemcmpImpl(vm sbpf.VM, addr1, addr2, n, resultAddr uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	cuOut = MemOpConsume(cuIn, n)
	if cuOut < 0 {
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
func SyscallMemsetImpl(vm sbpf.VM, dst, c, n uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	cuOut = MemOpConsume(cuIn, n)
	if cuOut < 0 {
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
