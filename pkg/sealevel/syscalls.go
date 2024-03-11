package sealevel

import (
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/sbpf"
)

// Syscalls creates a registry of all Sealevel syscalls.
func Syscalls(f *features.Features) sbpf.SyscallRegistry {
	reg := sbpf.NewSyscallRegistry()
	reg.Register("abort", SyscallAbort)
	reg.Register("sol_panic_", SyscallPanic)

	reg.Register("sol_log_", SyscallLog)
	reg.Register("sol_log_64_", SyscallLog64)
	reg.Register("sol_log_pubkey", SyscallLogPubkey)
	reg.Register("sol_log_compute_units_", SyscallLogCUs)
	reg.Register("sol_log_data", SyscallLogData)

	reg.Register("sol_sha256", SyscallSha256)
	reg.Register("sol_keccak256", SyscallKeccak256)
	reg.Register("sol_blake3", SyscallBlake3)
	reg.Register("sol_secp256k1_recover", SyscallSecp256k1Recover)

	reg.Register("sol_memcpy_", SyscallMemcpy)
	reg.Register("sol_memcmp_", SyscallMemcmp)
	reg.Register("sol_memset_", SyscallMemset)
	reg.Register("sol_memmove_", SyscallMemmove)

	reg.Register("sol_create_program_address", SyscallCreateProgramAddress)
	reg.Register("sol_try_find_program_address", SyscallTryFindProgramAddress)

	reg.Register("sol_get_stack_height", SyscallGetStackHeight)
	reg.Register("sol_get_return_data", SyscallGetReturnData)
	reg.Register("sol_set_return_data", SyscallSetReturnData)

	reg.Register("sol_get_clock_sysvar", SyscallGetClockSysvar)
	reg.Register("sol_get_rent_sysvar", SyscallGetRentSysvar)
	reg.Register("sol_get_epoch_schedule_sysvar", SyscallGetEpochScheduleSysvar)

	if f.IsActive(features.EnablePartitionedEpochReward) {
		reg.Register("sol_get_epoch_rewards_sysvar", SyscallGetEpochRewardsSysvar)
	}

	if f.IsActive(features.LastRestartSlotSysvar) {
		reg.Register("sol_get_last_restart_slot_sysvar", SyscallGetLastRestartSlotSysvar)
	}

	// non-"feature gated" syscalls still yet to implement:
	// 		sol_get_processed_sibling_instruction
	// 		sol_invoke_signed_c
	// 		sol_invoke_signed_rust

	// feature gated syscalls yet to implement:
	//		sol_curve_validate_point (disabled)
	//		sol_curve_group_op (disabled)
	//		sol_curve_multiscalar_mul (disabled)
	//		sol_alt_bn128_group_op (disabled)
	//		sol_big_mod_exp (disabled)
	//		sol_poseidon (disabled)
	//		sol_remaining_compute_units (disabled)
	//		sol_alt_bn128_compression (disabled)
	//		sol_get_fees_sysvar (deprecated & now disabled via feature gate JAN1trEUEtZjgXYzNBYHU9DYd7GnThhXfFP7SzPXkPsG)
	//		sol_alloc_free_ (deprecated & now disabled via feature gate 79HWsX9rpnnJBPcdNURVqygpMAfxdrAirzAGAVmf92im)

	return reg
}
