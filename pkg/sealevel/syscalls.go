package sealevel

import (
	"go.firedancer.io/radiance/pkg/sbpf"
)

var registry = Syscalls()

// Syscalls creates a registry of all Sealevel syscalls.
func Syscalls() sbpf.SyscallRegistry {
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

	// non-"feature gated" syscalls still yet to implement:
	// 		sol_get_clock_sysvar
	// 		sol_get_epoch_schedule_sysvar
	// 		sol_get_rent_sysvar
	// 		sol_get_processed_sibling_instruction
	// 		sol_get_stack_height
	// 		sol_set_return_data
	// 		sol_get_return_data
	// 		sol_invoke_signed_c
	// 		sol_invoke_signed_rust

	return reg
}

func syscallCtx(vm sbpf.VM) *Execution {
	return vm.VMContext().(*Execution)
}
