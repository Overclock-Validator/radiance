package features

import "go.firedancer.io/radiance/pkg/solana"

type FeatureGate struct {
	Name    string
	Address solana.Address
}

var StopTruncatingStringsInSyscalls = FeatureGate{Name: "StopTruncatingStringsInSyscalls", Address: solana.MustAddress("16FMCmgLzCNNz6eTwGanbyN2ZxvTBSLuQ6DZhgeMshg")}
