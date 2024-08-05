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
)
