package features

import (
	"go.firedancer.io/radiance/pkg/fflags"
	"go.firedancer.io/radiance/pkg/solana"
)

var StopTruncatingStringsInSyscalls = fflags.Register(solana.MustAddress("16FMCmgLzCNNz6eTwGanbyN2ZxvTBSLuQ6DZhgeMshg"), "StopTruncatingStringsInSyscalls")

func init() {
	fflags.WithoutFeature(StopTruncatingStringsInSyscalls)
}
