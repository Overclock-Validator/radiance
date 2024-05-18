package features

import (
	"go.firedancer.io/radiance/pkg/base58"
)

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
var TimelyVoteCredits = FeatureGate{Name: "TimelyVoteCredits", Address: base58.MustDecodeFromString("2oXpeh141pPZCTCFHBsvCwG2BtaHZZAtrVhwaxSy6brS")}
var ReduceStakeWarmupCooldown = FeatureGate{Name: "ReduceStakeWarmupCooldown", Address: base58.MustDecodeFromString("GwtDQBghCTBgmX2cpEGNPxTEBUTQRaDMGTr5qychdGMj")}
var StakeRaiseMinimumDelegationTo1Sol = FeatureGate{Name: "StakeRaiseMinimumDelegationTo1Sol", Address: base58.MustDecodeFromString("9onWzzvCzNC2jfhxxeqRgs5q7nFAAKpCUvkj6T6GJK9i")}
var StakeRedelegateInstruction = FeatureGate{Name: "StakeRedelegateInstruction", Address: base58.MustDecodeFromString("2KKG3C6RBnxQo9jVVrbzsoSh41TDXLK7gBc9gduyxSzW")}
var RequireRentExemptSplitDestination = FeatureGate{Name: "RequireRentExemptSplitDestination", Address: base58.MustDecodeFromString("D2aip4BBr8NPWtU9vLrwrBvbuaQ8w1zV38zFLxx4pfBV")}
var DeprecateExecutableMetaUpdateInBpfLoader = FeatureGate{Name: "DeprecateExecutableMetaUpdateInBpfLoader", Address: base58.MustDecodeFromString("k6uR1J9VtKJnTukBV2Eo15BEy434MBg8bT6hHQgmU8v")}
