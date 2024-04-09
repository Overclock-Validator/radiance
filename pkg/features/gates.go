package features

import (
	"go.firedancer.io/radiance/pkg/base58"
)

type FeatureGate struct {
	Name    string
	Address [32]byte
}

var StopTruncatingStringsInSyscalls = FeatureGate{Name: "StopTruncatingStringsInSyscalls", Address: base58.MustDecodeFromString("16FMCmgLzCNNz6eTwGanbyN2ZxvTBSLuQ6DZhgeMshg")}
var EnablePartitionedEpochReward = FeatureGate{Name: "EnablePartitionedEpochReward", Address: base58.MustDecodeFromString("41tVp5qR1XwWRt5WifvtSQyuxtqQWJgEK8w91AtBqSwP")}
var LastRestartSlotSysvar = FeatureGate{Name: "LastRestartSlotSysvar", Address: base58.MustDecodeFromString("HooKD5NC9QNxk25QuzCssB8ecrEzGt6eXEPBUxWp1LaR")}
var Libsecp256k1FailOnBadCount = FeatureGate{Name: "Libsecp256k1FailOnBadCount", Address: base58.MustDecodeFromString("8aXvSuopd1PUj7UhehfXJRg6619RHp8ZvwTyyJHdUYsj")}
var Libsecp256k1FailOnBadCount2 = FeatureGate{Name: "Libsecp256k1FailOnBadCount2", Address: base58.MustDecodeFromString("54KAoNiUERNoWWUhTWWwXgym94gzoXFVnHyQwPA18V9A")}
