package global

import (
	"github.com/Overclock-Validator/mithril/pkg/accounts"
	"github.com/Overclock-Validator/mithril/pkg/bank"
	"github.com/Overclock-Validator/mithril/pkg/features"
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
	return &GlobalCtx{Features: *features}
}
