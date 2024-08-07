package sealevel

import (
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/sbpf"
)

// Syscalls creates a registry of all Sealevel syscalls.
func Syscalls(f *features.Features, isDeploy bool) sbpf.SyscallRegistry {
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
	reg.Register("sol_poseidon", SyscallPoseidon)

	if f.IsActive(features.Curve25519SyscallEnabled) {
		reg.Register("sol_curve_validate_point", SyscallValidatePoint)
		reg.Register("sol_curve_multiscalar_mul", SyscallCurveMultiscalarMultiplication)
		reg.Register("sol_curve_group_op", SyscallCurveGroupOps)
	}

	if f.IsActive(features.EnableAltbn128CompressionSyscall) {
		reg.Register("sol_alt_bn128_compression", SyscallAltBn128Compression)
	}

	if f.IsActive(features.EnableAltBn128Syscall) {
		reg.Register("sol_alt_bn128_group_op", SyscallAltBn128)
	}

	reg.Register("sol_memcpy_", SyscallMemcpy)
	reg.Register("sol_memcmp_", SyscallMemcmp)
	reg.Register("sol_memset_", SyscallMemset)
	reg.Register("sol_memmove_", SyscallMemmove)

	if !isDeploy {
		reg.Register("sol_alloc_free_", SyscallAllocFree)
	}

	reg.Register("sol_create_program_address", SyscallCreateProgramAddress)
	reg.Register("sol_try_find_program_address", SyscallTryFindProgramAddress)

	reg.Register("sol_get_stack_height", SyscallGetStackHeight)
	reg.Register("sol_get_return_data", SyscallGetReturnData)
	reg.Register("sol_set_return_data", SyscallSetReturnData)
	reg.Register("sol_get_processed_sibling_instruction", SyscallGetProcessedSiblingInstruction)

	reg.Register("sol_get_clock_sysvar", SyscallGetClockSysvar)
	reg.Register("sol_get_rent_sysvar", SyscallGetRentSysvar)
	reg.Register("sol_get_epoch_schedule_sysvar", SyscallGetEpochScheduleSysvar)

	if f.IsActive(features.EnablePartitionedEpochReward) {
		reg.Register("sol_get_epoch_rewards_sysvar", SyscallGetEpochRewardsSysvar)
	}

	if f.IsActive(features.LastRestartSlotSysvar) {
		reg.Register("sol_get_last_restart_slot_sysvar", SyscallGetLastRestartSlotSysvar)
	}

	var SyscallInvokeSignedC = sbpf.SyscallFunc5(SyscallInvokeSignedCImpl)
	var SyscallInvokeSignedRust = sbpf.SyscallFunc5(SyscallInvokeSignedRustImpl)

	reg.Register("sol_invoke_signed_c", SyscallInvokeSignedC)
	reg.Register("sol_invoke_signed_rust", SyscallInvokeSignedRust)

	return reg
}
