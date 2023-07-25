package sealevel

import (
	"errors"
	"fmt"

	"go.firedancer.io/radiance/pkg/sbpf"
)

func SyscallAbortImpl(_ sbpf.VM, _ int) (r0 uint64, cuOut int, err error) {
	err = errors.New("aborted")
	return
}

var SyscallAbort = sbpf.SyscallFunc0(SyscallAbortImpl)

// SyscallPanicImpl is the implementation for the panic (sol_panic_) syscall.
// The Labs client implementation does CU accounting, checks for NULL
// termination, validates the utf8 string, etc, but we don't actually
// need to do this because this syscall returns an error and aborts the
// transaction either way, and the exact error returned does not matter for
// consensus.
func SyscallPanicImpl(vm sbpf.VM, fileNameAddr, len, line, column uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	filenameData, err := vm.Translate(fileNameAddr, len, false)
	if err != nil {
		return
	}

	err = fmt.Errorf("SBF program Panicked in %s at %d:%d", string(filenameData), line, column)
	return
}

var SyscallPanic = sbpf.SyscallFunc4(SyscallPanicImpl)
