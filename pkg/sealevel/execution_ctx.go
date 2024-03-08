package sealevel

import (
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/global"
)

type ExecutionCtx struct {
	Log                Logger
	Accounts           accounts.Accounts
	transactionContext TransactionCtx
	globalCtx          global.GlobalCtx
}
