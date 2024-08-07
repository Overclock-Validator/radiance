package sealevel

import (
	"bytes"
	"encoding/binary"

	"go.firedancer.io/radiance/pkg/sbpf"
)

// SyscallGetClockSysvarImpl is an implementation of the sol_get_clock_sysvar syscall
func SyscallGetClockSysvarImpl(vm sbpf.VM, addr uint64) (uint64, error) {
	execCtx := executionCtx(vm)

	cost := uint64(CUSyscallBaseCost + SysvarClockStructLen)
	err := execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return syscallCuErr()
	}

	var clockDst []byte
	clockDst, err = vm.Translate(addr, SysvarClockStructLen, true)
	if err != nil {
		return syscallErr(err)
	}

	var clock SysvarClock
	clock, err = ReadClockSysvar(getAccounts(vm))
	if err != nil {
		return syscallErr(err)
	}

	binary.LittleEndian.PutUint64(clockDst[:8], clock.Slot)
	binary.LittleEndian.PutUint64(clockDst[8:16], uint64(clock.EpochStartTimestamp))
	binary.LittleEndian.PutUint64(clockDst[16:24], clock.Epoch)
	binary.LittleEndian.PutUint64(clockDst[24:32], clock.LeaderScheduleEpoch)
	binary.LittleEndian.PutUint64(clockDst[32:40], uint64(clock.UnixTimestamp))

	return syscallSuccess(0)
}

var SyscallGetClockSysvar = sbpf.SyscallFunc1(SyscallGetClockSysvarImpl)

// SyscallGetRentSysvarImpl is an implementation of the sol_get_rent_sysvar syscall
func SyscallGetRentSysvarImpl(vm sbpf.VM, addr uint64) (uint64, error) {
	execCtx := executionCtx(vm)

	cost := uint64(CUSyscallBaseCost + SysvarRentStructLen)
	err := execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return syscallCuErr()
	}

	rentDst, err := vm.Translate(addr, SysvarRentStructLen, true)
	if err != nil {
		return syscallErr(err)
	}

	rent, err := ReadRentSysvar(getAccounts(vm))
	if err != nil {
		return syscallErr(err)
	}

	binary.LittleEndian.PutUint64(rentDst[:8], rent.LamportsPerUint8Year)
	binary.LittleEndian.PutUint64(rentDst[8:16], uint64(rent.ExemptionThreshold))
	rentDst[16] = rent.BurnPercent

	return syscallSuccess(0)
}

var SyscallGetRentSysvar = sbpf.SyscallFunc1(SyscallGetRentSysvarImpl)

// SyscallGetEpochScheduleSysvarImpl is an implementation of the sol_get_epoch_schedule_sysvar syscall
func SyscallGetEpochScheduleSysvarImpl(vm sbpf.VM, addr uint64) (uint64, error) {
	execCtx := executionCtx(vm)

	cost := uint64(CUSyscallBaseCost + SysvarEpochScheduleStructLen)
	err := execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return syscallCuErr()
	}

	epochScheduleDst, err := vm.Translate(addr, SysvarEpochScheduleStructLen, true)
	if err != nil {
		return syscallErr(err)
	}

	epochSchedule, err := ReadEpochScheduleSysvar(getAccounts(vm))
	if err != nil {
		return syscallErr(err)
	}

	binary.LittleEndian.PutUint64(epochScheduleDst[:8], epochSchedule.SlotsPerEpoch)
	binary.LittleEndian.PutUint64(epochScheduleDst[8:16], uint64(epochSchedule.LeaderScheduleSlotOffset))

	if epochSchedule.Warmup {
		epochScheduleDst[16] = 1
	} else {
		epochScheduleDst[16] = 0
	}

	binary.LittleEndian.PutUint64(epochScheduleDst[17:25], epochSchedule.FirstNormalEpoch)
	binary.LittleEndian.PutUint64(epochScheduleDst[25:33], epochSchedule.FirstNormalSlot)

	return syscallSuccess(0)
}

var SyscallGetEpochScheduleSysvar = sbpf.SyscallFunc1(SyscallGetEpochScheduleSysvarImpl)

// SyscallGetEpochRewardsSysvarImpl is an implementation of the sol_get_epoch_rewards_sysvar syscall
func SyscallGetEpochRewardsSysvarImpl(vm sbpf.VM, addr uint64) (uint64, error) {
	execCtx := executionCtx(vm)

	cost := uint64(CUSyscallBaseCost + SysvarEpochRewardsStructLen)
	err := execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return syscallCuErr()
	}

	epochRewardsDst, err := vm.Translate(addr, SysvarEpochRewardsStructLen, true)
	if err != nil {
		return syscallErr(err)
	}

	epochRewards, err := ReadEpochRewardsSysvar(getAccounts(vm))
	if err != nil {
		return syscallErr(err)
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, epochRewards.DistributionStartingBlockHeight)
	binary.Write(buf, binary.LittleEndian, epochRewards.NumPartitions)
	binary.Write(buf, binary.LittleEndian, epochRewards.ParentBlockhash)
	binary.Write(buf, binary.LittleEndian, epochRewards.TotalPoints)
	binary.Write(buf, binary.LittleEndian, epochRewards.TotalRewards)
	binary.Write(buf, binary.LittleEndian, epochRewards.DistributedRewards)
	binary.Write(buf, binary.LittleEndian, epochRewards.Active)

	copy(epochRewardsDst, buf.Bytes())

	return syscallSuccess(0)
}

var SyscallGetEpochRewardsSysvar = sbpf.SyscallFunc1(SyscallGetEpochRewardsSysvarImpl)

// SyscallGetLastRestartSlotSysvarImpl is an implementation of the sol_get_last_restart_slot_sysvar syscall
func SyscallGetLastRestartSlotSysvarImpl(vm sbpf.VM, addr uint64) (uint64, error) {
	execCtx := executionCtx(vm)

	cost := uint64(CUSyscallBaseCost + SysvarLastRestartSlotStructLen)
	err := execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return syscallCuErr()
	}

	lastRestartSlotDst, err := vm.Translate(addr, SysvarLastRestartSlotStructLen, true)
	if err != nil {
		return syscallErr(err)
	}

	lrs := ReadLastRestartSlotSysvar(getAccounts(vm))

	binary.LittleEndian.PutUint64(lastRestartSlotDst[:8], lrs.LastRestartSlot)

	return syscallSuccess(0)
}

var SyscallGetLastRestartSlotSysvar = sbpf.SyscallFunc1(SyscallGetLastRestartSlotSysvarImpl)
