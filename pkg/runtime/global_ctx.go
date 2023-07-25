package runtime

import (
	"go.firedancer.io/radiance/pkg/features"
)

// WIP

type GlobalCtx struct {
	Accounts Accounts
	Leader   [32]byte
	Features features.Features
	// TODO: Bank
}

func NewGlobalCtxDefault() *GlobalCtx {
	features := features.NewFeaturesDefault()
	return &GlobalCtx{Features: features}
}
