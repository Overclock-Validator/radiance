package loader

import (
	"debug/elf"
	"fmt"
	"io"

	"github.com/Overclock-Validator/mithril/pkg/sbpf"
)

// The following ELF loading rules seem mostly arbitrary.
// For the sake of cleanliness, this loader doesn't process
// some badly malformed ELFs that would pass on Solana mainnet.
// The Solana protocol is being improved in this area.

// copy allocates program buffers and copies ELF contents.
func (l *Loader) copy() error {
	l.progRange = newAddrRange()
	l.rodatas = make([]addrRange, 0, 4)
	if err := l.getText(); err != nil {
		return err
	}
	if err := l.mapSections(); err != nil {
		return err
	}
	if err := l.copySections(); err != nil {
		return err
	}
	return nil
}

// getText remembers the range of .text in the program buffer
func (l *Loader) getText() error {
	if err := l.checkSectionAddrs(l.shText); err != nil {
		return fmt.Errorf("invalid .text: %w", err)
	}
	l.textRange = addrRange{min: l.shText.Off, max: l.shText.Off + l.shText.Size}
	return nil
}

// mapRodataLike reserves ranges for sections in the program buffer
func (l *Loader) mapSections() error {
	// Walk all non-standard rodata sections
	iter := l.newShTableIter()
	for iter.Next() && iter.Err() == nil {
		i, sh := iter.Index(), iter.Item()

		// Skip standard sections
		sectionName, err := l.getString(&l.shShstrtab, sh.Name, maxSectionNameLen)
		if err != nil {
			return fmt.Errorf("getString: %w", err)
		}
		switch sectionName {
		case ".text", ".rodata", ".data.rel.ro", ".eh_frame":
			// ok
		default:
			continue
		}

		if err := l.checkSectionAddrs(&sh); err != nil {
			return fmt.Errorf("invalid rodata-like section %d: %w", i, err)
		}

		// Section overlap check & bounds tracking
		section := addrRange{min: sh.Off, max: sh.Off + sh.Size}
		if section.len() == 0 {
			continue
		}
		if l.progRange.containsRange(section) {
			// TODO rbpf probably doesn't have this restriction
			return fmt.Errorf("rodata section %d overlaps with other section", i)
		}
		l.progRange.insert(section)

		if section.min != l.textRange.min {
			l.rodatas = append(l.rodatas, section)
		}
	}
	return iter.Err()
}

func (l *Loader) checkSectionAddrs(sh *elf.Section64) error {
	// TODO Support true vaddr ELFs

	if sh.Size > l.fileSize {
		return io.ErrUnexpectedEOF
	}
	if sh.Addr != sh.Off {
		return fmt.Errorf("section physical address out-of-place")
	}

	// Ensure section within VM program range
	vaddr := clampAddUint64(sbpf.VaddrProgram, sh.Addr)
	vaddrEnd := vaddr + sh.Size
	if vaddrEnd < vaddr || vaddrEnd > sbpf.VaddrStack {
		return fmt.Errorf("section virtual address out-of-bounds")
	}

	return nil
}

// copySections copies text and rodata-like sections from the ELF into VM memory.
func (l *Loader) copySections() error {
	if l.progRange.len() == 0 {
		// TODO what is the correct behavior here?
		return fmt.Errorf("program is empty (???)")
	}
	l.progRange.extendToFit(0)

	// Allocate!
	l.program = make([]byte, l.fileSize)

	// Read data from ELF file
	for _, section := range l.rodatas {
		if err := l.copySection(section); err != nil {
			return err
		}
	}
	if err := l.copySection(l.textRange); err != nil {
		return err
	}

	// Special sub-slice for text
	l.text = l.getRange(l.textRange)

	return nil
}

func (l *Loader) copySection(section addrRange) (err error) {
	off, size := int64(section.min), int64(section.len())
	rd := io.NewSectionReader(l.rd, off, size)
	_, err = io.ReadFull(rd, l.program[section.min:section.max])
	return
}

func (l *Loader) getRange(section addrRange) []byte {
	return l.program[section.min:section.max]
}
