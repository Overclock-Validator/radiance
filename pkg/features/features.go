package features

import (
	"go.firedancer.io/radiance/pkg/fflags"
	"go.firedancer.io/radiance/pkg/solana"
)

var f fflags.Features

var StopTruncatingStringsInSyscalls = fflags.Register(solana.MustAddress("16FMCmgLzCNNz6eTwGanbyN2ZxvTBSLuQ6DZhgeMshg"), "StopTruncatingStringsInSyscalls")

func init() {
	f.WithoutFeature(StopTruncatingStringsInSyscalls)
}
