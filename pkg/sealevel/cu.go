package sealevel

const (
	CUSyscallBaseCost                         = 100
	CULog64Units                              = 100
	CULogPubkeyUnits                          = 100
	CUMemOpBaseCost                           = 10
	CUCpiBytesPerUnit                         = 250
	CUSha256BaseCost                          = 85
	CUSha256ByteCost                          = 1
	CUCreateProgramAddressUnits               = 1500
	CUSecP256k1RecoverCost                    = 25000
	CUInvokeUnits                             = 1000
	CUConfigProcessorDefaultComputeUnits      = 450
	CUSystemProgramDefaultComputeUnits        = 150
	CUVoteProgramDefaultComputeUnits          = 2100
	CUStakeProgramDefaultComputeUnits         = 750
	CUSha256MaxSlices                         = 20000
	CUMaxCpiInstructionSize                   = 1280
	CUUpgradeableLoaderComputeUnits           = 2370
	CUDeprecatedLoaderComputeUnits            = 1140
	CUDefaultLoaderComputeUnits               = 570
	CUHeapCostDefault                         = 8
	CUAddressLookupTableDefaultComputeUnits   = 750
	CUComputeBudgetProgramDefaultComputeUnits = 150
	CUCurve25519EdwardsValidatePointCost      = 159
	CUCurve25519RistrettoValidatePointCost    = 169
	CUCurve25519EdwardsMsmBaseCost            = 2273
	CUCurve25519EdwardsMsmIncrementalCost     = 758
	CUCurve25519RistrettoMsmBaseCost          = 2303
	CUCurve25519RistrettoMsmIncrementalCost   = 788
	CUCurve25519EdwardsAddCost                = 473
	CUCurve25519EdwardsSubCost                = 475
	CUCurve25519EdwardsMulCost                = 2177
	CUCurve25519RistrettoAddCost              = 521
	CUCurve25519RistrettoSubCost              = 519
	CUCurve25519RistrettoMulCost              = 2208
	CUBn128G1Compress                         = 30
	CUBn128G1Decompress                       = 398
	CUBn128G2Compress                         = 86
	CUBn128G2Decompress                       = 13610
	CUBn128AdditionCost                       = 334
	CUBn128MultiplicationCost                 = 3840
	CUBn128PairingOnePairCostFirst            = 36364
	CUBn128PairingOnePairCostOther            = 12121
)
