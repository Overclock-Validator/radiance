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
var EnableBpfLoaderSetAuthorityCheckedIx = FeatureGate{Name: "EnableBpfLoaderSetAuthorityCheckedIx", Address: base58.MustDecodeFromString("5x3825XS7M2A3Ekbn5VGGkvFoAg5qrRWkTrY4bARP1GL")}
var LoosenCpiSizeRestriction = FeatureGate{Name: "LoosenCpiSizeRestriction", Address: base58.MustDecodeFromString("GDH5TVdbTPUpRnXaRyQqiKUa7uZAbZ28Q2N9bhbKoMLm")}
var IncreaseTxAccountLockLimit = FeatureGate{Name: "IncreaseTxAccountLockLimit", Address: base58.MustDecodeFromString("9LZdXeKGeBV6hRLdxS1rHbHoEUsKqesCC2ZAPTPKJAbK")}
var VoteStateAddVoteLatency = FeatureGate{Name: "VoteStateAddVoteLatency", Address: base58.MustDecodeFromString("7axKe5BTYBDD87ftzWbk5DfzWMGyRvqmWTduuo22Yaqy")}
var AllowCommissionDecreaseAtAnyTime = FeatureGate{Name: "AllowCommissionDecreaseAtAnyTime", Address: base58.MustDecodeFromString("decoMktMcnmiq6t3u7g5BfgcQu91nKZr6RvMYf9z1Jb")}
var CommissionUpdatesOnlyAllowedInFirstHalfOfEpoch = FeatureGate{Name: "CommissionUpdatesOnlyAllowedInFirstHalfOfEpoch", Address: base58.MustDecodeFromString("noRuG2kzACwgaY7TVmLRnUNPLKNVQE1fb7X55YWBehp")}
