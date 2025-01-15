package sbpf

// Stack is the VM's call frame stack.
//
// # Memory stack
//
// The memory stack resides in addressable memory at VaddrStack.
//
// It is split into statically sized stack frames (StackFrameSize).
// Each frame stores spilled function arguments and local variables.
// The frame pointer (r10) points to the highest address in the current frame.
//
// New frames get allocated upwards.
// Each frame is followed by a gap of size StackFrameSize.
//
//	[0x1_0000_0000]: Frame
//	[0x1_0000_1000]: Gap
//	[0x1_0000_2000]: Frame
//	[0x1_0000_3000]: Gap
//	...
//
// # Shadow stack
//
// The shadow stack is not directly accessible from SBF.
// It stores return addresses and caller-preserved registers.
type Stack struct {
	mem    []byte
	sp     uint64
	shadow []Frame
}

// Frame is an entry on the shadow stack.
type Frame struct {
	FramePtr uint64
	NVRegs   [4]uint64
	RetAddr  int64
}

// StackFrameSize is the addressable memory within a stack frame.
//
// Note that this constant cannot be changed trivially.
const StackFrameSize = 0x1000

// StackDepth is the max frame count of the stack.
const StackDepth = 64

func NewStack() Stack {
	s := Stack{
		mem:    make([]byte, (StackDepth+1)*StackFrameSize),
		sp:     VaddrStack,
		shadow: make([]Frame, 1, StackDepth),
	}
	s.shadow[0] = Frame{
		FramePtr: VaddrStack + StackFrameSize,
	}
	return s
}

// GetFramePtr returns the current frame pointer.
func (s *Stack) GetFramePtr() uint64 {
	return s.shadow[len(s.shadow)-1].FramePtr
}

// GetFrame returns the stack frame memory slice containing the frame pointer.
//
// The returned slice starts at the location within the frame as indicated by the address.
// To get the full frame, align the provided address by StackFrameSize.
//
// Returns nil if the program tries to address a gap or out-of-bounds memory.
func (s *Stack) GetFrame(addr uint32) []byte {
	hi, lo := addr/StackFrameSize, addr%StackFrameSize
	if hi > StackDepth || hi%2 == 1 {
		return nil
	}
	pos := hi / 2
	off := pos * StackFrameSize
	return s.mem[off+lo: /*off+StackFrameSize*/]
}

// Push allocates a new call frame.
//
// Saves the given nonvolatile regs and return address.
// Returns the new frame pointer.
func (s *Stack) Push(nvRegs *[4]uint64, ret int64) (fp uint64, ok bool) {
	if ok = len(s.shadow) < cap(s.shadow); !ok {
		return
	}

	fp = s.GetFramePtr() + 2*StackFrameSize
	s.shadow = s.shadow[:len(s.shadow)+1]
	s.shadow[len(s.shadow)-1] = Frame{
		FramePtr: fp,
		NVRegs:   *nvRegs,
		RetAddr:  ret,
	}
	s.sp = fp - StackFrameSize
	return
}

// Pop exits the last call frame.
//
// Writes saved nonvolatile regs into provided slice.
// Returns saved return address, new frame pointer.
// Sets `ok` to false if no call frames are left.
func (s *Stack) Pop(nvRegs *[4]uint64) (fp uint64, ret int64, ok bool) {
	if len(s.shadow) <= 1 {
		ok = false
		return
	}

	var frame Frame
	frame, s.shadow = s.shadow[len(s.shadow)-1], s.shadow[:len(s.shadow)-1]

	fp = s.GetFramePtr()
	*nvRegs = frame.NVRegs
	ret = frame.RetAddr
	ok = true
	return
}
