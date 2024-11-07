package sbpf

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"strings"
	"unsafe"

	"go.firedancer.io/radiance/pkg/cu"
	"go.firedancer.io/radiance/pkg/global"
)

// Interpreter implements the SBF core in pure Go.
type Interpreter struct {
	textVA uint64
	text   []byte
	ro     []byte
	stack  Stack
	heap   []byte
	input  []byte

	entry    uint64
	heapSize uint64

	syscalls          map[uint32]Syscall
	funcs             map[uint32]int64
	vmContext         any
	globalCtx         *global.GlobalCtx
	trace             TraceSink
	enableTracing     bool
	computeMeter      *cu.ComputeMeter
	dueInstrCount     uint64
	prevInstrMeter    uint64
	initialInstrMeter uint64
}

type TraceSink interface {
	Printf(format string, v ...any)
}

// NewInterpreter creates a new interpreter instance for a program execution.
//
// The caller must create a new interpreter object for every new execution.
// In other words, Run may only be called once per interpreter.
func NewInterpreter(globalCtx *global.GlobalCtx, p *Program, opts *VMOpts) *Interpreter {
	return &Interpreter{
		textVA:            p.TextVA,
		text:              p.Text,
		ro:                p.RO,
		stack:             NewStack(),
		heap:              make([]byte, opts.HeapMax),
		input:             opts.Input,
		entry:             p.Entrypoint,
		syscalls:          opts.Syscalls,
		funcs:             p.Funcs,
		vmContext:         opts.Context,
		globalCtx:         globalCtx,
		trace:             opts.Tracer,
		computeMeter:      opts.ComputeMeter,
		prevInstrMeter:    opts.ComputeMeter.Remaining(),
		initialInstrMeter: opts.ComputeMeter.Remaining(),
		enableTracing:     opts.EnableTracing,
	}
}

// Run executes the program.
//
// This function may panic given code that doesn't pass the static verifier.
func (ip *Interpreter) Run() (ret uint64, cuConsumed uint64, err error) {
	var r [11]uint64
	r[1] = VaddrInput
	r[10] = ip.stack.GetFramePtr()
	// TODO frame pointer
	pc := int64(ip.entry)

	// Design notes
	// - The interpreter is deliberately implemented in a single big loop,
	//   to give the compiler more creative liberties, and avoid escaping hot data to the heap.
	// - uint64(int32(x)) performs sign extension. Most ALU64 instructions make use of this.
	// - The static verifier imposes invariants on the bytecode.
	//   The interpreter may panic when it notices these invariants are violated (e.g. invalid opcode)

mainLoop:
	for i := 0; true; i++ {
		// Fetch
		ins := ip.getSlot(pc)
		if ip.enableTracing {
			regsDump := fmt.Sprintf("%016x, %016x, %016x, %016x, %016x, %016x, %016x, %016x, %016x, %016x, %016x",
				r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10])
			fmt.Printf("% 5d [%s]: %s\n",
				i, strings.ToUpper(regsDump), disassemble(ins /*todo*/, 0))
		}

		err = ip.computeMeter.Consume(1)
		if err != nil {
			break mainLoop
		}

		// Execute
		switch ins.Op() {
		case OpLdxb:
			vma := uint64(int64(r[ins.Src()]) + int64(ins.Off()))
			var v uint8
			v, err = ip.Read8(vma)
			r[ins.Dst()] = uint64(v)
			pc++
		case OpLdxh:
			vma := uint64(int64(r[ins.Src()]) + int64(ins.Off()))
			var v uint16
			v, err = ip.Read16(vma)
			r[ins.Dst()] = uint64(v)
			pc++
		case OpLdxw:
			vma := uint64(int64(r[ins.Src()]) + int64(ins.Off()))
			var v uint32
			v, err = ip.Read32(vma)
			r[ins.Dst()] = uint64(v)
			pc++
		case OpLdxdw:
			vma := uint64(int64(r[ins.Src()]) + int64(ins.Off()))
			var v uint64
			v, err = ip.Read64(vma)
			r[ins.Dst()] = v
			pc++
		case OpStb:
			vma := uint64(int64(r[ins.Dst()]) + int64(ins.Off()))
			err = ip.Write8(vma, uint8(ins.Uimm()))
			pc++
		case OpSth:
			vma := uint64(int64(r[ins.Dst()]) + int64(ins.Off()))
			err = ip.Write16(vma, uint16(ins.Uimm()))
			pc++
		case OpStw:
			vma := uint64(int64(r[ins.Dst()]) + int64(ins.Off()))
			err = ip.Write32(vma, ins.Uimm())
			pc++
		case OpStdw:
			vma := uint64(int64(r[ins.Dst()]) + int64(ins.Off()))
			err = ip.Write64(vma, uint64(ins.Imm()))
			pc++
		case OpStxb:
			vma := uint64(int64(r[ins.Dst()]) + int64(ins.Off()))
			err = ip.Write8(vma, uint8(r[ins.Src()]))
			pc++
		case OpStxh:
			vma := uint64(int64(r[ins.Dst()]) + int64(ins.Off()))
			err = ip.Write16(vma, uint16(r[ins.Src()]))
			pc++
		case OpStxw:
			vma := uint64(int64(r[ins.Dst()]) + int64(ins.Off()))
			err = ip.Write32(vma, uint32(r[ins.Src()]))
			pc++
		case OpStxdw:
			vma := uint64(int64(r[ins.Dst()]) + int64(ins.Off()))
			err = ip.Write64(vma, r[ins.Src()])
			pc++
		case OpAdd32Imm:
			r[ins.Dst()] = uint64(int32(r[ins.Dst()]) + ins.Imm())
			pc++
		case OpAdd32Reg:
			r[ins.Dst()] = uint64(int32(r[ins.Dst()]) + int32(r[ins.Src()]))
			pc++
		case OpAdd64Imm:
			r[ins.Dst()] += uint64(ins.Imm())
			pc++
		case OpAdd64Reg:
			r[ins.Dst()] += r[ins.Src()]
			pc++
		case OpSub32Imm:
			r[ins.Dst()] = uint64(int32(r[ins.Dst()]) - ins.Imm())
			pc++
		case OpSub32Reg:
			r[ins.Dst()] = uint64(int32(r[ins.Dst()]) - int32(r[ins.Src()]))
			pc++
		case OpSub64Imm:
			r[ins.Dst()] -= uint64(ins.Imm())
			pc++
		case OpSub64Reg:
			r[ins.Dst()] -= r[ins.Src()]
			pc++
		case OpMul32Imm:
			r[ins.Dst()] = uint64(int32(r[ins.Dst()]) * ins.Imm())
			pc++
		case OpMul32Reg:
			r[ins.Dst()] = uint64(int32(r[ins.Dst()]) * int32(r[ins.Src()]))
			pc++
		case OpMul64Imm:
			r[ins.Dst()] *= uint64(ins.Imm())
			pc++
		case OpMul64Reg:
			r[ins.Dst()] *= r[ins.Src()]
			pc++
		case OpDiv32Imm:
			r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) / ins.Uimm())
			pc++
		case OpDiv32Reg:
			if src := uint32(r[ins.Src()]); src != 0 {
				r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) / src)
			} else {
				err = ExcDivideByZero
			}
			pc++
		case OpDiv64Imm:
			r[ins.Dst()] /= uint64(ins.Imm())
			pc++
		case OpDiv64Reg:
			if src := r[ins.Src()]; src != 0 {
				r[ins.Dst()] /= src
			} else {
				err = ExcDivideByZero
			}
			pc++
		case OpSdiv32Imm:
			if int32(r[ins.Dst()]) == math.MinInt32 && ins.Imm() == -1 {
				err = ExcDivideOverflow
			}
			r[ins.Dst()] = uint64(int32(r[ins.Dst()]) / ins.Imm())
			pc++
		case OpSdiv32Reg:
			if src := int32(r[ins.Src()]); src != 0 {
				if int32(r[ins.Dst()]) == math.MinInt32 && src == -1 {
					err = ExcDivideOverflow
				}
				r[ins.Dst()] = uint64(int32(r[ins.Dst()]) / src)
			} else {
				err = ExcDivideByZero
			}
			pc++
		case OpSdiv64Imm:
			if int64(r[ins.Dst()]) == math.MinInt64 && ins.Imm() == -1 {
				err = ExcDivideOverflow
			}
			r[ins.Dst()] = uint64(int64(r[ins.Dst()]) / int64(ins.Imm()))
			pc++
		case OpSdiv64Reg:
			if src := int64(r[ins.Src()]); src != 0 {
				if int64(r[ins.Dst()]) == math.MinInt64 && src == -1 {
					err = ExcDivideOverflow
				}
				r[ins.Dst()] = uint64(int64(r[ins.Dst()]) / src)
			} else {
				err = ExcDivideByZero
			}
			pc++
		case OpOr32Imm:
			r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) | ins.Uimm())
			pc++
		case OpOr32Reg:
			r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) | uint32(r[ins.Src()]))
			pc++
		case OpOr64Imm:
			r[ins.Dst()] |= uint64(ins.Imm())
			pc++
		case OpOr64Reg:
			r[ins.Dst()] |= r[ins.Src()]
			pc++
		case OpAnd32Imm:
			r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) & ins.Uimm())
			pc++
		case OpAnd32Reg:
			r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) & uint32(r[ins.Src()]))
			pc++
		case OpAnd64Imm:
			r[ins.Dst()] &= uint64(ins.Imm())
			pc++
		case OpAnd64Reg:
			r[ins.Dst()] &= r[ins.Src()]
			pc++
		case OpLsh32Imm:
			r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) << ins.Uimm())
			pc++
		case OpLsh32Reg:
			r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) << uint32(r[ins.Src()]&0x1f))
			pc++
		case OpLsh64Imm:
			r[ins.Dst()] <<= uint64(ins.Imm())
			pc++
		case OpLsh64Reg:
			r[ins.Dst()] <<= r[ins.Src()] & 0x3f
			pc++
		case OpRsh32Imm:
			r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) >> ins.Uimm())
			pc++
		case OpRsh32Reg:
			r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) >> uint32(r[ins.Src()]&0x1f))
			pc++
		case OpRsh64Imm:
			r[ins.Dst()] >>= uint64(ins.Imm())
			pc++
		case OpRsh64Reg:
			r[ins.Dst()] >>= r[ins.Src()] & 0x3f
			pc++
		case OpNeg32:
			r[ins.Dst()] = uint64(-int32(r[ins.Dst()]))
			pc++
		case OpNeg64:
			r[ins.Dst()] = uint64(-int64(r[ins.Dst()]))
			pc++
		case OpMod32Imm:
			r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) % ins.Uimm())
			pc++
		case OpMod32Reg:
			if src := uint32(r[ins.Src()]); src != 0 {
				r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) % src)
			} else {
				err = ExcDivideByZero
			}
			pc++
		case OpMod64Imm:
			r[ins.Dst()] %= uint64(ins.Imm())
			pc++
		case OpMod64Reg:
			if src := r[ins.Src()]; src != 0 {
				r[ins.Dst()] %= src
			} else {
				err = ExcDivideByZero
			}
			pc++
		case OpXor32Imm:
			r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) ^ ins.Uimm())
			pc++
		case OpXor32Reg:
			r[ins.Dst()] = uint64(uint32(r[ins.Dst()]) ^ uint32(r[ins.Src()]))
			pc++
		case OpXor64Imm:
			r[ins.Dst()] ^= uint64(ins.Imm())
			pc++
		case OpXor64Reg:
			r[ins.Dst()] ^= r[ins.Src()]
			pc++
		case OpMov32Imm:
			r[ins.Dst()] = uint64(ins.Uimm())
			pc++
		case OpMov32Reg:
			r[ins.Dst()] = r[ins.Src()]
			pc++
		case OpMov64Imm:
			r[ins.Dst()] = uint64(ins.Imm())
			pc++
		case OpMov64Reg:
			r[ins.Dst()] = r[ins.Src()]
			pc++
		case OpArsh32Imm:
			r[ins.Dst()] = uint64(int32(r[ins.Dst()]) >> ins.Uimm())
			pc++
		case OpArsh32Reg:
			r[ins.Dst()] = uint64(int32(r[ins.Dst()]) >> uint32(r[ins.Src()]))
			pc++
		case OpArsh64Imm:
			r[ins.Dst()] = uint64(int64(r[ins.Dst()]) >> ins.Imm())
			pc++
		case OpArsh64Reg:
			r[ins.Dst()] = uint64(int64(r[ins.Dst()]) >> (r[ins.Src()]))
			pc++
		case OpLe:
			switch ins.Uimm() {
			case 16:
				r[ins.Dst()] &= math.MaxUint16
			case 32:
				r[ins.Dst()] &= math.MaxUint32
			case 64:
				r[ins.Dst()] &= math.MaxUint64
			default:
				panic("invalid le instruction")
			}
			pc++
		case OpBe:
			switch ins.Uimm() {
			case 16:
				r[ins.Dst()] = uint64(bits.ReverseBytes16(uint16(r[ins.Dst()])))
			case 32:
				r[ins.Dst()] = uint64(bits.ReverseBytes32(uint32(r[ins.Dst()])))
			case 64:
				r[ins.Dst()] = bits.ReverseBytes64(r[ins.Dst()])
			default:
				panic("invalid be instruction")
			}
			pc++
		case OpLddw:
			i := (pc+1)*SlotSize + 4
			msh := int32(binary.LittleEndian.Uint32(ip.text[i : i+4]))
			r[ins.Dst()] = uint64(ins.Uimm()) | (uint64(msh) << 32)
			pc += 2
		case OpJa:
			pc += int64(ins.Off())
			pc++
		case OpJeqImm:
			if r[ins.Dst()] == uint64(ins.Imm()) {
				pc += int64(ins.Off())
			}
			pc++
		case OpJeqReg:
			if r[ins.Dst()] == r[ins.Src()] {
				pc += int64(ins.Off())
			}
			pc++
		case OpJgtImm:
			if r[ins.Dst()] > uint64(ins.Imm()) {
				pc += int64(ins.Off())
			}
			pc++
		case OpJgtReg:
			if r[ins.Dst()] > r[ins.Src()] {
				pc += int64(ins.Off())
			}
			pc++
		case OpJgeImm:
			if r[ins.Dst()] >= uint64(ins.Imm()) {
				pc += int64(ins.Off())
			}
			pc++
		case OpJgeReg:
			if r[ins.Dst()] >= r[ins.Src()] {
				pc += int64(ins.Off())
			}
			pc++
		case OpJltImm:
			if r[ins.Dst()] < uint64(ins.Imm()) {
				pc += int64(ins.Off())
			}
			pc++
		case OpJltReg:
			if r[ins.Dst()] < r[ins.Src()] {
				pc += int64(ins.Off())
			}
			pc++
		case OpJleImm:
			if r[ins.Dst()] <= uint64(ins.Imm()) {
				pc += int64(ins.Off())
			}
			pc++
		case OpJleReg:
			if r[ins.Dst()] <= r[ins.Src()] {
				pc += int64(ins.Off())
			}
			pc++
		case OpJsetImm:
			if r[ins.Dst()]&uint64(ins.Imm()) != 0 {
				pc += int64(ins.Off())
			}
			pc++
		case OpJsetReg:
			if r[ins.Dst()]&r[ins.Src()] != 0 {
				pc += int64(ins.Off())
			}
			pc++
		case OpJneImm:
			if r[ins.Dst()] != uint64(ins.Imm()) {
				pc += int64(ins.Off())
			}
			pc++
		case OpJneReg:
			if r[ins.Dst()] != r[ins.Src()] {
				pc += int64(ins.Off())
			}
			pc++
		case OpJsgtImm:
			if int64(r[ins.Dst()]) > int64(ins.Imm()) {
				pc += int64(ins.Off())
			}
			pc++
		case OpJsgtReg:
			if int64(r[ins.Dst()]) > int64(r[ins.Src()]) {
				pc += int64(ins.Off())
			}
			pc++
		case OpJsgeImm:
			if int64(r[ins.Dst()]) >= int64(ins.Imm()) {
				pc += int64(ins.Off())
			}
			pc++
		case OpJsgeReg:
			if int64(r[ins.Dst()]) >= int64(r[ins.Src()]) {
				pc += int64(ins.Off())
			}
			pc++
		case OpJsltImm:
			if int64(r[ins.Dst()]) < int64(ins.Imm()) {
				pc += int64(ins.Off())
			}
			pc++
		case OpJsltReg:
			if int64(r[ins.Dst()]) < int64(r[ins.Src()]) {
				pc += int64(ins.Off())
			}
			pc++
		case OpJsleImm:
			if int64(r[ins.Dst()]) <= int64(ins.Imm()) {
				pc += int64(ins.Off())
			}
			pc++
		case OpJsleReg:
			if int64(r[ins.Dst()]) <= int64(r[ins.Src()]) {
				pc += int64(ins.Off())
			}
			pc++
		case OpCall:
			// TODO use src reg hint
			if sc, ok := ip.syscalls[ins.Uimm()]; ok {
				r[0], err = sc.Invoke(ip, r[1], r[2], r[3], r[4], r[5])
				pc++
			} else if target, ok := ip.funcs[ins.Uimm()]; ok {
				r[10], ok = ip.stack.Push((*[4]uint64)(r[6:10]), pc+1)
				if !ok {
					err = ExcCallDepth
				}
				pc = target
			} else {
				err = ExcCallDest{ins.Uimm()}
			}
		case OpCallx:
			target := r[ins.Uimm()]
			target &= ^(uint64(0x7))
			var ok bool
			r[10], ok = ip.stack.Push((*[4]uint64)(r[6:10]), pc+1)
			if !ok {
				err = ExcCallDepth
			}
			if target < ip.textVA || target >= VaddrStack || target >= ip.textVA+uint64(len(ip.text)) {
				err = NewExcBadAccess(target, 8, false, "jump out-of-bounds")
			}
			pc = int64((target - ip.textVA) / 8)
		case OpExit:
			var ok bool
			r[10], pc, ok = ip.stack.Pop((*[4]uint64)(r[6:10]))
			if !ok {
				ret = r[0]
				break mainLoop
			}
		default:
			panic(fmt.Sprintf("unimplemented opcode %#02x", ins.Op()))
		}

		// Post execute
		if err == cu.ErrComputeExceeded {
			err = ExcOutOfCU
		}

		if err != nil {
			exc := &Exception{
				PC:     pc,
				Detail: err,
			}
			if IsLongIns(ins.Op()) {
				exc.PC-- // fix reported PC
			}

			return 0, 0, exc
		}
	}

	cuConsumed = ip.initialInstrMeter - ip.computeMeter.Remaining()

	return
}

func (ip *Interpreter) getSlot(pc int64) Slot {
	return GetSlot(ip.text[pc*SlotSize:])
}

func (ip *Interpreter) VMContext() any {
	return ip.vmContext
}

func (ip *Interpreter) GlobalCtx() *global.GlobalCtx {
	return ip.globalCtx
}

func (ip *Interpreter) HeapMax() uint64 {
	return uint64(len(ip.heap))
}

func (ip *Interpreter) HeapSize() uint64 {
	return ip.heapSize
}

func (ip *Interpreter) UpdateHeapSize(size uint64) {
	ip.heapSize = size
}

func (ip *Interpreter) translateInternal(addr uint64, size uint64, write bool) (unsafe.Pointer, error) {
	// TODO exhaustive testing against rbpf
	// TODO review generated asm for performance

	hi, lo := addr>>32, addr&math.MaxUint32
	switch hi {
	case VaddrProgram >> 32:
		if write {
			return nil, NewExcBadAccess(addr, size, write, "write to program")
		}
		if lo+size > uint64(len(ip.ro)) {
			return nil, NewExcBadAccess(addr, size, write, "out-of-bounds program read")
		}
		return unsafe.Pointer(&ip.ro[lo]), nil
	case VaddrStack >> 32:
		mem := ip.stack.GetFrame(uint32(addr))
		if size > uint64(len(mem)) {
			return nil, NewExcBadAccess(addr, size, write, "out-of-bounds stack access")
		}
		return unsafe.Pointer(&mem[0]), nil
	case VaddrHeap >> 32:
		if lo+size > uint64(len(ip.heap)) {
			return nil, NewExcBadAccess(addr, size, write, "out-of-bounds heap access")
		}
		return unsafe.Pointer(&ip.heap[lo]), nil
	case VaddrInput >> 32:
		if lo+size > uint64(len(ip.input)) {
			return nil, NewExcBadAccess(addr, size, write, "out-of-bounds input access")
		}
		return unsafe.Pointer(&ip.input[lo]), nil
	default:
		return nil, NewExcBadAccess(addr, size, write, "unmapped region")
	}
}

func (ip *Interpreter) Translate(addr uint64, size uint64, write bool) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}

	ptr, err := ip.translateInternal(addr, size, write)
	if err != nil {
		return nil, err
	}

	mem := unsafe.Slice((*uint8)(ptr), size)
	return mem, nil
}

func (ip *Interpreter) DueInstrCount() uint64 {
	return ip.dueInstrCount
}

func (ip *Interpreter) PrevInstrMeter() uint64 {
	return ip.prevInstrMeter
}

func (ip *Interpreter) SetPrevInstrMeter(num uint64) {
	ip.prevInstrMeter = num
}

func (ip *Interpreter) ComputeMeter() *cu.ComputeMeter {
	return ip.computeMeter
}

func (ip *Interpreter) Read(addr uint64, p []byte) error {
	ptr, err := ip.translateInternal(addr, uint64(len(p)), false)
	if err != nil {
		return err
	}
	mem := unsafe.Slice((*uint8)(ptr), len(p))
	copy(p, mem)
	return nil
}

func (ip *Interpreter) Read8(addr uint64) (uint8, error) {
	ptr, err := ip.translateInternal(addr, 1, false)
	if err != nil {
		return 0, err
	}
	return *(*uint8)(ptr), nil
}

// TODO is it safe and portable to deref unaligned integer types?

func (ip *Interpreter) Read16(addr uint64) (uint16, error) {
	ptr, err := ip.translateInternal(addr, 2, false)
	if err != nil {
		return 0, err
	}
	return *(*uint16)(ptr), nil
}

func (ip *Interpreter) Read32(addr uint64) (uint32, error) {
	ptr, err := ip.translateInternal(addr, 4, false)
	if err != nil {
		return 0, err
	}
	return *(*uint32)(ptr), nil
}

func (ip *Interpreter) Read64(addr uint64) (uint64, error) {
	ptr, err := ip.translateInternal(addr, 8, false)
	if err != nil {
		return 0, err
	}
	return *(*uint64)(ptr), nil
}

func (ip *Interpreter) Write(addr uint64, p []byte) error {
	ptr, err := ip.translateInternal(addr, uint64(len(p)), true)
	if err != nil {
		return err
	}
	mem := unsafe.Slice((*uint8)(ptr), len(p))
	copy(mem, p)
	return nil
}

func (ip *Interpreter) Write8(addr uint64, x uint8) error {
	ptr, err := ip.translateInternal(addr, 1, true)
	if err != nil {
		return err
	}
	*(*uint8)(ptr) = x
	return nil
}

func (ip *Interpreter) Write16(addr uint64, x uint16) error {
	ptr, err := ip.translateInternal(addr, 2, true)
	if err != nil {
		return err
	}
	*(*uint16)(ptr) = x
	return nil
}

func (ip *Interpreter) Write32(addr uint64, x uint32) error {
	ptr, err := ip.translateInternal(addr, 4, true)
	if err != nil {
		return err
	}
	*(*uint32)(ptr) = x
	return nil
}

func (ip *Interpreter) Write64(addr uint64, x uint64) error {
	ptr, err := ip.translateInternal(addr, 8, false)
	if err != nil {
		return err
	}
	*(*uint64)(ptr) = x
	return nil
}
