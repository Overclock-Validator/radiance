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

// SyscallGetRentSysvarImpl is an implementation of the sol_get_rent_sysvar syscall
func SyscallGetRentSysvarImpl(vm sbpf.VM, addr uint64, cuIn int) (r0 uint64, cuOut int, err error) {

	cost := CUSyscallBaseCost + SysvarRentStructLen
	cuOut, err = cu.ConsumeComputeMeter(cuIn, cost)
	if err != nil {
		return
	}

	rentDst, err := vm.Translate(addr, SysvarRentStructLen, true)
	if err != nil {
		return
	}

	rent := ReadRentSysvar(getAccounts(vm))

	binary.LittleEndian.PutUint64(rentDst[:8], rent.LamportsPerUint8Year)
	binary.LittleEndian.PutUint64(rentDst[8:16], uint64(rent.ExemptionThreshold))
	rentDst[16] = rent.BurnPercent

	r0 = 0
	return
}

var SyscallGetRentSysvar = sbpf.SyscallFunc1(SyscallGetRentSysvarImpl)

// SyscallGetEpochScheduleSysvarImpl is an implementation of the sol_get_epoch_schedule_sysvar syscall
func SyscallGetEpochScheduleSysvarImpl(vm sbpf.VM, addr uint64, cuIn int) (r0 uint64, cuOut int, err error) {

	cost := CUSyscallBaseCost + SysvarEpochScheduleStructLen
	cuOut, err = cu.ConsumeComputeMeter(cuIn, cost)
	if err != nil {
		return
	}

	epochScheduleDst, err := vm.Translate(addr, SysvarEpochScheduleStructLen, true)
	if err != nil {
		return
	}

	epochSchedule := ReadEpochScheduleSysvar(getAccounts(vm))

	binary.LittleEndian.PutUint64(epochScheduleDst[:8], epochSchedule.SlotsPerEpoch)
	binary.LittleEndian.PutUint64(epochScheduleDst[8:16], uint64(epochSchedule.LeaderScheduleSlotOffset))

	if epochSchedule.Warmup {
		epochScheduleDst[16] = 1
	} else {
		epochScheduleDst[16] = 0
	}

	binary.LittleEndian.PutUint64(epochScheduleDst[17:25], epochSchedule.FirstNormalEpoch)
	binary.LittleEndian.PutUint64(epochScheduleDst[25:33], epochSchedule.FirstNormalSlot)

	r0 = 0
	return
}

var SyscallGetEpochScheduleSysvar = sbpf.SyscallFunc1(SyscallGetEpochScheduleSysvarImpl)

// SyscallGetEpochRewardsSysvarImpl is an implementation of the sol_get_epoch_rewards_sysvar syscall
func SyscallGetEpochRewardsSysvarImpl(vm sbpf.VM, addr uint64, cuIn int) (r0 uint64, cuOut int, err error) {

	cost := CUSyscallBaseCost + SysvarEpochRewardsStructLen
	cuOut, err = cu.ConsumeComputeMeter(cuIn, cost)
	if err != nil {
		return
	}

	epochRewardsDst, err := vm.Translate(addr, SysvarEpochRewardsStructLen, true)
	if err != nil {
		return
	}

	epochRewards := ReadEpochRewardsSysvar(getAccounts(vm))

	binary.LittleEndian.PutUint64(epochRewardsDst[:8], epochRewards.TotalRewards)
	binary.LittleEndian.PutUint64(epochRewardsDst[8:16], epochRewards.DistributedRewards)
	binary.LittleEndian.PutUint64(epochRewardsDst[8:16], epochRewards.DistributionCompleteBlockHeight)

	r0 = 0
	return
}

var SyscallGetEpochRewardsSysvar = sbpf.SyscallFunc1(SyscallGetEpochRewardsSysvarImpl)

// SyscallGetLastRestartSlotSysvarImpl is an implementation of the sol_get_last_restart_slot_sysvar syscall
func SyscallGetLastRestartSlotSysvarImpl(vm sbpf.VM, addr uint64, cuIn int) (r0 uint64, cuOut int, err error) {

	cost := CUSyscallBaseCost + SysvarLastRestartSlotStructLen
	cuOut, err = cu.ConsumeComputeMeter(cuIn, cost)
	if err != nil {
		return
	}

	lastRestartSlotDst, err := vm.Translate(addr, SysvarLastRestartSlotStructLen, true)
	if err != nil {
		return
	}

	lrs := ReadLastRestartSlotSysvar(getAccounts(vm))

	binary.LittleEndian.PutUint64(lastRestartSlotDst[:8], lrs.LastRestartSlot)

	r0 = 0
	return
}

var SyscallGetLastRestartSlotSysvar = sbpf.SyscallFunc1(SyscallGetLastRestartSlotSysvarImpl)
