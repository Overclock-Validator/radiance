package global

import (
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/bank"
	"go.firedancer.io/radiance/pkg/features"
)

// WIP

type GlobalCtx struct {
	Accounts *accounts.Accounts
	Leader   [32]byte
	Features features.Features
	Bank     *bank.Bank
	// TODO: Bank
}

func NewGlobalCtxDefault() *GlobalCtx {
	features := features.NewFeaturesDefault()
	return &GlobalCtx{Features: features}
}
