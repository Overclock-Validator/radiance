// Package loader implements an ELF loader for the Sealevel virtual machine.
//
// Based on https://docs.rs/solana_rbpf/latest/solana_rbpf/elf_parser/index.html
package loader

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"

	"github.com/Overclock-Validator/mithril/pkg/sbpf"
)

// TODO Fuzz
// TODO Differential fuzz against rbpf

// Loader is based on solana_rbpf::elf_parser
type Loader struct {
	// File containing ELF
	rd       io.ReaderAt
	fileSize uint64

	syscalls        *sbpf.SyscallRegistry
	elfDeployChecks bool

	// ELF data structures
	eh         elf.Header64
	phLoad     elf.Prog64
	phDynamic  *elf.Prog64
	shShstrtab elf.Section64
	shText     *elf.Section64
	shSymtab   *elf.Section64
	shStrtab   *elf.Section64
	shDynstr   *elf.Section64
	shDynamic  *elf.Section64
	shDynsym   *elf.Section64
	dynamic    [DT_NUM]uint64
	relocsIter *tableIter[elf.Rel64]
	dynSymIter *tableIter[elf.Sym64]

	// Program section/segment mappings
	// Uses physical addressing
	rodatas   []addrRange
	textRange addrRange
	progRange addrRange

	// Contains most of ELF (.text and rodata-like)
	// Non-loaded sections are zeroed
	program    []byte
	text       []byte
	entrypoint uint64 // program counter

	// Symbols
	funcs map[uint32]int64
}

// Bounds checks
const (
	// 64 MiB max program size.
	// Allows loader to use unchecked math when adding 32-bit offsets.
	maxFileLen = 1 << 26
)

// EF_SBF_V2 is the SBFv2 ELF flag
const EF_SBF_V2 = 0x20

// DT_NUM is the number of ELF generic dynamic entry types
const DT_NUM = 35

// NewLoaderFromBytes creates an ELF loader from a byte slice.
func NewLoaderFromBytes(buf []byte) (*Loader, error) {
	if len(buf) > maxFileLen {
		return nil, fmt.Errorf("ELF file too large")
	}
	l := &Loader{
		rd:       bytes.NewReader(buf),
		fileSize: uint64(len(buf)),
	}
	return l, nil
}

func NewLoaderWithSyscalls(buf []byte, syscalls *sbpf.SyscallRegistry, elfDeployChecks bool) (*Loader, error) {
	if len(buf) > maxFileLen {
		return nil, fmt.Errorf("ELF file too large")
	}
	l := &Loader{
		rd:              bytes.NewReader(buf),
		fileSize:        uint64(len(buf)),
		syscalls:        syscalls,
		elfDeployChecks: elfDeployChecks,
	}
	return l, nil
}

// Load parses, loads, and relocates an SBF program.
//
// This loader differs from rbpf in a few ways:
// We don't support spec bugs, we relocate after loading.
func (l *Loader) Load() (*sbpf.Program, error) {
	if err := l.parse(); err != nil {
		return nil, err
	}
	if err := l.copy(); err != nil {
		return nil, err
	}
	if err := l.relocate(); err != nil {
		return nil, err
	}
	return l.getProgram(), nil
}

func (l *Loader) getProgram() *sbpf.Program {
	return &sbpf.Program{
		RO:         l.program,
		Text:       l.text,
		TextVA:     sbpf.VaddrProgram + l.textRange.min,
		Entrypoint: l.entrypoint,
		Funcs:      l.funcs,
	}
}
