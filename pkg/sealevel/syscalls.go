package sealevel

import (
	"go.firedancer.io/radiance/pkg/sbpf"
)

var registry = Syscalls()

// Syscalls creates a registry of all Sealevel syscalls.
func Syscalls() sbpf.SyscallRegistry {
	reg := sbpf.NewSyscallRegistry()
	reg.Register("abort", SyscallAbort)
	reg.Register("sol_log_", SyscallLog)
	reg.Register("sol_log_64_", SyscallLog64)
	reg.Register("sol_log_compute_units_", SyscallLogCUs)
	reg.Register("sol_log_pubkey", SyscallLogPubkey)
	reg.Register("sol_memcpy_", SyscallMemcpy)
	reg.Register("sol_memmove_", SyscallMemmove)
	reg.Register("sol_memcmp_", SyscallMemcmp)
	reg.Register("sol_memset_", SyscallMemset)
	reg.Register("sol_sha256", SyscallSha256)
	reg.Register("sol_blake3", SyscallBlake3)
	reg.Register("sol_keccak256", SyscallKeccak256)
	reg.Register("sol_panic_", SyscallPanic)
	reg.Register("sol_create_program_address", SyscallCreateProgramAddress)
	reg.Register("sol_try_find_program_address", SyscallTryFindProgramAddress)
	return reg
}

func syscallCtx(vm sbpf.VM) *Execution {
	return vm.VMContext().(*Execution)
}
