package sbpf

import (
	"errors"
	"fmt"

	"go.firedancer.io/radiance/pkg/cu"
	"go.firedancer.io/radiance/pkg/global"
)

// VM is the virtual machine abstraction, implemented by each executor.
type VM interface {
	VMContext() any
	GlobalCtx() *global.GlobalCtx

	HeapMax() uint64
	HeapSize() uint64
	UpdateHeapSize(size uint64)

	Translate(addr uint64, size uint64, write bool) ([]byte, error)

	Read(addr uint64, p []byte) error
	Read8(addr uint64) (uint8, error)
	Read16(addr uint64) (uint16, error)
	Read32(addr uint64) (uint32, error)
	Read64(addr uint64) (uint64, error)

	Write(addr uint64, p []byte) error
	Write8(addr uint64, x uint8) error
	Write16(addr uint64, x uint16) error
	Write32(addr uint64, x uint32) error
	Write64(addr uint64, x uint64) error
}

// VMOpts specifies virtual machine parameters.
type VMOpts struct {
	// Machine parameters
	HeapMax  int
	Syscalls SyscallRegistry
	Tracer   TraceSink

	// Execution parameters
	Context      any // passed to syscalls
	MaxCU        int
	ComputeMeter *cu.ComputeMeter
	Input        []byte // mapped at VaddrInput
}

type Exception struct {
	PC     int64
	Detail error
}

func (e *Exception) Error() string {
	return fmt.Sprintf("exception at %d: %s", e.PC, e.Detail)
}

func (e *Exception) Unwrap() error {
	return e.Detail
}

// Exception codes.
var (
	ExcDivideByZero   = errors.New("division by zero")
	ExcDivideOverflow = errors.New("divide overflow")
	ExcOutOfCU        = errors.New("compute unit overrun")
	ExcCallDepth      = errors.New("call depth exceeded")
)

type ExcBadAccess struct {
	Addr   uint64
	Size   uint64
	Write  bool
	Reason string
}

func NewExcBadAccess(addr uint64, size uint64, write bool, reason string) ExcBadAccess {
	return ExcBadAccess{
		Addr:   addr,
		Size:   size,
		Write:  write,
		Reason: reason,
	}
}

func (e ExcBadAccess) Error() string {
	return fmt.Sprintf("bad memory access at %#x (size=%d write=%v), reason: %s", e.Addr, e.Size, e.Write, e.Reason)
}

type ExcCallDest struct {
	Imm uint32
}

func (e ExcCallDest) Error() string {
	return fmt.Sprintf("unknown symbol or syscall 0x%08x", e.Imm)
}
