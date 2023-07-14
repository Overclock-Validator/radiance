package sealevel

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"

	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/fflags"
	"go.firedancer.io/radiance/pkg/sbpf"
	"go.firedancer.io/radiance/pkg/sbpf/cu"
)

var f fflags.Features

func SyscallAbortImpl(_ sbpf.VM, _ int) (r0 uint64, cuOut int, err error) {
	err = errors.New("aborted")
	return
}

var SyscallAbort = sbpf.SyscallFunc0(SyscallAbortImpl)

// SyscallPanicImpl is the implementation for the panic (sol_panic_) syscall.
func SyscallPanicImpl(vm sbpf.VM, fileNameAddr, len, line, column uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	cuOut = cu.ConsumeLowerBound(cuIn, int(len), 0)
	if cuOut < 0 {
		return
	}

	data, err := vm.Translate(fileNameAddr, len, false)
	if err != nil {
		return
	}

	var filenameBytes []byte
	if f.HasFeature(features.StopTruncatingStringsInSyscalls) {
		filenameBytes = data
	} else {
		idx := bytes.IndexByte(data, 0)
		if idx == -1 {
			err = InvalidLength
			return
		}
		filenameBytes = data[0:idx]
	}

	if !utf8.ValidString(string(filenameBytes)) {
		err = InvalidString
		return
	}

	err = fmt.Errorf("SBF program Panicked in %s at %d:%d", string(filenameBytes), line, column)
	return
}

var SyscallPanic = sbpf.SyscallFunc4(SyscallPanicImpl)
