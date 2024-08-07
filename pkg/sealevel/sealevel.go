package sealevel

import (
	"bytes"

	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/sbpf"
)

func executionCtx(vm sbpf.VM) *ExecutionCtx {
	return vm.VMContext().(*ExecutionCtx)
}

func transactionCtx(vm sbpf.VM) *TransactionCtx {
	return vm.VMContext().(*ExecutionCtx).TransactionContext
}

func getAccounts(vm sbpf.VM) *accounts.Accounts {
	return vm.VMContext().(*ExecutionCtx).GlobalCtx.Accounts
}

func (t *TransactionCtx) newVMOpts(params *Params) *sbpf.VMOpts {
	execution := &ExecutionCtx{
		Log: new(LogRecorder),
	}
	var buf bytes.Buffer
	params.Serialize(&buf)
	return &sbpf.VMOpts{
		HeapMax:  32 * 1024,
		Syscalls: Syscalls(&params.Features, false),
		Context:  execution,
		MaxCU:    1_400_000,
		Input:    buf.Bytes(),
	}
}
