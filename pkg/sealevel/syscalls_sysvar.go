package sealevel

import (
	"encoding/binary"

	"go.firedancer.io/radiance/pkg/sbpf"
	"go.firedancer.io/radiance/pkg/sbpf/cu"
)

// SyscallGetClockSysvarImpl is an implementation of the sol_get_clock_sysvar syscall
func SyscallGetClockSysvarImpl(vm sbpf.VM, addr uint64, cuIn int) (r0 uint64, cuOut int, err error) {

	cost := CUSyscallBaseCost + SysvarClockStructLen
	cuOut, err = cu.ConsumeComputeMeter(cuIn, cost)
	if err != nil {
		return
	}

	clockDst, err := vm.Translate(addr, SysvarClockStructLen, true)
	if err != nil {
		return
	}

	clock := ReadClockSysvar(getAccounts(vm))

	binary.LittleEndian.PutUint64(clockDst[:8], clock.Slot)
	binary.LittleEndian.PutUint64(clockDst[8:16], uint64(clock.EpochStartTimestamp))
	binary.LittleEndian.PutUint64(clockDst[16:24], clock.Epoch)
	binary.LittleEndian.PutUint64(clockDst[24:32], clock.LeaderScheduleEpoch)
	binary.LittleEndian.PutUint64(clockDst[32:40], uint64(clock.UnixTimestamp))

	r0 = 0
	return
}

var SyscallGetClockSysvar = sbpf.SyscallFunc1(SyscallGetClockSysvarImpl)