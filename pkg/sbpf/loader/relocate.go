package loader

import (
	"debug/elf"
	"encoding/binary"
	"fmt"

	"github.com/Overclock-Validator/mithril/pkg/sbpf"
)

// relocate applies ELF relocations (for syscalls and position-independent code).
func (l *Loader) relocate() error {
	l.funcs = make(map[uint32]int64)
	if err := l.fixupRelativeCalls(); err != nil {
		return err
	}
	if err := l.applyDynamicRelocs(); err != nil {
		return err
	}
	if err := l.getEntrypoint(); err != nil {
		return err
	}
	return nil
}

func (l *Loader) fixupRelativeCalls() error {
	// TODO does invariant text.size%8 == 0 hold?
	insCount := l.textRange.len() / sbpf.SlotSize
	buf := l.getRange(l.textRange)
	for i := uint64(0); i < insCount; i++ {
		off := i * sbpf.SlotSize
		slot := sbpf.GetSlot(buf[off : off+sbpf.SlotSize])

		isCall := slot.Op() == sbpf.OpCall && slot.Imm() != -1
		if !isCall {
			continue
		}

		target := int64(i) + 1 + int64(slot.Imm())
		if target < 0 || target >= int64(insCount) {
			return fmt.Errorf("call ins out of bounds")
		}

		hash, err := l.registerFunc(uint64(target))
		if err != nil {
			return err
		}

		var newImm [4]byte
		binary.LittleEndian.PutUint32(newImm[:], hash)
		copy(buf[off+4:off+8], newImm[:])
	}
	return nil
}

func (l *Loader) registerFunc(target uint64) (uint32, error) {
	hash := sbpf.PCHash(target)

	// check for collision with syscall
	if l.syscalls != nil && l.syscalls.ExistsByHash(hash) {
		return 0, fmt.Errorf("symbol hash collision with syscall")
	}

	//if _, ok := l.funcs[hash]; ok {
	//	return 0, fmt.Errorf("symbol hash collision for func at=%d hash=%#08x", target, hash)
	//}

	l.funcs[hash] = int64(target)
	return hash, nil
}

func (l *Loader) applyDynamicRelocs() error {
	iter := l.relocsIter
	if iter == nil {
		return nil
	}
	for iter.Next() && iter.Err() == nil {
		reloc := iter.Item()
		if err := l.applyReloc(&reloc); err != nil {
			return err
		}
	}
	return iter.Err()
}

func (l *Loader) applyReloc(reloc *elf.Rel64) error {
	// TODO rOff is not checked
	// Need to have a virtual write target here
	rOff := reloc.Off
	rType := R_BPF(elf.R_TYPE64(reloc.Info))
	rSym := elf.R_SYM64(reloc.Info)

	switch rType {
	case R_BPF_64_64:
		sym, err := l.getDynsym(rSym)
		if err != nil {
			return err
		}

		// Add immediate as offset to symbol
		relAddr := binary.LittleEndian.Uint32(l.program[rOff+4 : rOff+8])
		addr := clampAddUint64(sym.Value, uint64(relAddr))

		if addr < sbpf.VaddrProgram {
			addr += sbpf.VaddrProgram
		}

		// Write to imm field of two slots
		binary.LittleEndian.PutUint32(l.program[rOff+4:rOff+8], uint32(addr))
		binary.LittleEndian.PutUint32(l.program[rOff+12:rOff+16], uint32(addr>>32))
	case R_BPF_64_RELATIVE:
		if l.textRange.contains(rOff) {
			immLow := binary.LittleEndian.Uint32(l.program[rOff+4 : rOff+8])
			immHi := binary.LittleEndian.Uint32(l.program[rOff+12 : rOff+16])

			addr := (uint64(immHi) << 32) | uint64(immLow)
			if addr == 0 {
				return fmt.Errorf("invalid R_BPF_64_RELATIVE")
			}
			if addr < sbpf.VaddrProgram {
				addr += sbpf.VaddrProgram
			}

			// Write to imm field of two slots
			binary.LittleEndian.PutUint32(l.program[rOff+4:rOff+8], uint32(addr))
			binary.LittleEndian.PutUint32(l.program[rOff+12:rOff+16], uint32(addr>>32))
		} else {
			var addr uint64
			if l.eh.Flags == EF_SBF_V2 {
				addr = binary.LittleEndian.Uint64(l.program[rOff : rOff+8])
				if addr < sbpf.VaddrProgram {
					addr += sbpf.VaddrProgram
				}
			} else {
				addr = uint64(binary.LittleEndian.Uint32(l.program[rOff+4 : rOff+8]))
				addr = clampAddUint64(addr, sbpf.VaddrProgram)
			}
			binary.LittleEndian.PutUint64(l.program[rOff:rOff+8], addr)
		}
	case R_BPF_64_32:
		sym, err := l.getDynsym(rSym)
		if err != nil {
			return err
		}
		name, err := l.getDynstr(sym.Name)
		if err != nil {
			return err
		}

		var hash uint32
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Value != 0 {
			// Function call
			if !l.textRange.contains(sym.Value) {
				return fmt.Errorf("out-of-bounds R_BPF_64_32 function ref")
			}
			target := (sym.Value - l.textRange.min) / 8
			hash, err = l.registerFunc(target)
			if err != nil {
				return fmt.Errorf("R_BPF_64_32 function ref: %w", err)
			}
		} else {
			// Syscall
			hash = sbpf.SymbolHash(name)
			if l.elfDeployChecks {
				if !l.syscalls.ExistsByHash(hash) {
					return fmt.Errorf("deployment check failure - hash did not exist in syscall registry (%s)", name)
				}
			}
		}

		binary.LittleEndian.PutUint32(l.program[rOff+4:rOff+8], hash)
	default:
		return fmt.Errorf("unsupported reloc type %d", rType)
	}
	return nil
}

func (l *Loader) getEntrypoint() error {
	offset := l.eh.Entry - l.shText.Addr
	if offset%sbpf.SlotSize != 0 {
		return fmt.Errorf("invalid entrypoint")
	}
	l.entrypoint = offset / sbpf.SlotSize
	return nil
}

// Relocation types for eBPF.
type R_BPF int

const (
	R_BPF_NONE        R_BPF = 0
	R_BPF_64_64       R_BPF = 1
	R_BPF_64_RELATIVE R_BPF = 8
	R_BPF_64_32       R_BPF = 10
)
