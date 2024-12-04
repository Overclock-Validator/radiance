package sealevel

import "github.com/Overclock-Validator/mithril/pkg/accounts"

func addrObjectForLookup(execCtx *ExecutionCtx) *accounts.Accounts {
	if execCtx.SlotCtx != nil && execCtx.SlotCtx.Replay {
		return &execCtx.SlotCtx.Accounts
	} else {
		return &execCtx.Accounts
	}
}
