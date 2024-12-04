package sealevel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/Overclock-Validator/mithril/pkg/features"
	"github.com/gagliardetto/solana-go"
)

// Params is the data passed to programs via the Sealevel VM input segment.
type Params struct {
	Accounts  []AccountParam
	Data      []byte // per-instruction data
	ProgramID solana.PublicKey
	Features  features.Features
}

// ReallocSpace is the allowed length by which an account is allowed to grow.
const ReallocSpace = 1024 * 10

// ReallocAlign is the byte amount by which the data following a realloc is aligned.
const ReallocAlign = 8

// AccountParam is an account input to a program execution.
type AccountParam struct {
	IsDuplicate    bool
	DuplicateIndex uint8 // must not be 0xFF
	IsSigner       bool
	IsWritable     bool
	IsExecutable   bool
	Key            solana.PublicKey
	Owner          solana.PublicKey
	Lamports       uint64
	Data           []byte
	Padding        int // ignored, written by serializer
	RentEpoch      uint64
}

// Serialize writes the params to the provided buffer.
func (p *Params) Serialize(buf *bytes.Buffer) {
	buf.Reset()

	_ = binary.Write(buf, binary.LittleEndian, uint64(len(p.Accounts)))
	for i := range p.Accounts {
		acc := &p.Accounts[i]

		if acc.IsDuplicate {
			_, _ = buf.Write([]byte{acc.DuplicateIndex})
			_ = writeZeros(buf, 7)
			continue
		}
		_ = binary.Write(buf, binary.LittleEndian, uint8(0xFF))
		_ = binary.Write(buf, binary.LittleEndian, acc.IsSigner)
		_ = binary.Write(buf, binary.LittleEndian, acc.IsWritable)
		_ = binary.Write(buf, binary.LittleEndian, acc.IsExecutable)
		_ = writeZeros(buf, 4)
		_, _ = buf.Write(acc.Key[:])
		_, _ = buf.Write(acc.Owner[:])
		_ = binary.Write(buf, binary.LittleEndian, acc.Lamports)

		_ = binary.Write(buf, binary.LittleEndian, uint64(len(acc.Data)))
		// This account copy cannot be avoided without a significant redesign of the VM
		_, _ = buf.Write(acc.Data[:])

		acc.Padding = ReallocSpace
		if offset := buf.Len() % ReallocAlign; offset != 0 {
			acc.Padding += ReallocAlign - offset
		}
		_ = writeZeros(buf, acc.Padding)

		_ = binary.Write(buf, binary.LittleEndian, acc.RentEpoch)
	}

	_ = binary.Write(buf, binary.LittleEndian, uint64(len(p.Data)))
	_, _ = buf.Write(p.Data)

	_, err := buf.Write(p.ProgramID[:])
	if err != nil {
		panic("writes to buffer failed: " + err.Error()) // OOM
	}
}

// Update writes data modified by a program back to the params struct.
func (p *Params) Update(buf *bytes.Reader) error {
	// TODO authorization checks

	for i := 0; true; i++ {
		if i >= len(p.Accounts) {
			return fmt.Errorf("number of accounts changed")
		}
		acc := &p.Accounts[i]

		idx, err := buf.ReadByte()
		if err != nil {
			return err
		}
		if (!acc.IsDuplicate && idx != 0xFF) || acc.DuplicateIndex != idx {
			return fmt.Errorf("account order changed")
		}

		if idx != 0xFF {
			continue
		}

		// TODO is deferring error check okay here?
		_ = binary.Read(buf, binary.LittleEndian, &acc.IsSigner)
		_ = binary.Read(buf, binary.LittleEndian, &acc.IsWritable)
		_ = binary.Read(buf, binary.LittleEndian, &acc.IsExecutable)
		_, _ = buf.Seek(4, io.SeekCurrent)
		_, _ = buf.Read(acc.Key[:])
		_, _ = buf.Read(acc.Owner[:])
		_ = binary.Read(buf, binary.LittleEndian, &acc.Lamports)

		oldLen := uint64(len(acc.Data))
		var newLen uint64
		_ = binary.Read(buf, binary.LittleEndian, &newLen)
		if newLen < oldLen {
			return fmt.Errorf("attempted to shrink account")
		}
		if newLen > oldLen+ReallocSpace {
			return fmt.Errorf("attempted to grow account too much")
		}
		acc.Data, _ = io.ReadAll(io.LimitReader(buf, int64(newLen)))
		_, _ = buf.Seek(int64(acc.Padding-int(newLen-oldLen)), io.SeekCurrent)

		_ = binary.Read(buf, binary.LittleEndian, &acc.RentEpoch)
	}

	_, _ = buf.Seek(int64(len(p.Data)), io.SeekCurrent)
	_, err := buf.Read(p.ProgramID[:])
	return err
}

func writeZeros(b *bytes.Buffer, n int) error {
	_, err := io.Copy(b, io.LimitReader(zeroRd{}, int64(n)))
	return err
}

type zeroRd struct{}

func (zeroRd) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}
