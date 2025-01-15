package sealevel

import (
	"bytes"

	"github.com/Overclock-Validator/mithril/pkg/accounts"
	"github.com/Overclock-Validator/mithril/pkg/features"
	"github.com/Overclock-Validator/mithril/pkg/sbpf"
)

func executionCtx(vm sbpf.VM) *ExecutionCtx {
	return vm.VMContext().(*ExecutionCtx)
}

func getFeatures(vm sbpf.VM) *features.Features {
	return &executionCtx(vm).GlobalCtx.Features
}

func transactionCtx(vm sbpf.VM) *TransactionCtx {
	return vm.VMContext().(*ExecutionCtx).TransactionContext
}

func getAccounts(vm sbpf.VM) *accounts.Accounts {
	return &vm.VMContext().(*ExecutionCtx).Accounts
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
