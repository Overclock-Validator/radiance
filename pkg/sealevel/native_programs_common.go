package sealevel

import (
	"errors"

	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/base58"
)

const BpfLoaderUpgradeableAddrStr = "BPFLoaderUpgradeab1e11111111111111111111111"

var BpfLoaderUpgradeableAddr = base58.MustDecodeFromString(BpfLoaderUpgradeableAddrStr)

const BpfLoader2AddrStr = "BPFLoader2111111111111111111111111111111111"

var BpfLoader2Addr = base58.MustDecodeFromString(BpfLoader2AddrStr)

const BpfLoaderDeprecatedAddrStr = "BPFLoader1111111111111111111111111111111111"

var BpfLoaderDeprecatedAddr = base58.MustDecodeFromString(BpfLoaderDeprecatedAddrStr)

const NativeLoaderAddrStr = "NativeLoader1111111111111111111111111111111"

var NativeLoaderAddr = base58.MustDecodeFromString(NativeLoaderAddrStr)

const ConfigProgramAddrStr = "Config1111111111111111111111111111111111111"

var ConfigProgramAddr = base58.MustDecodeFromString(ConfigProgramAddrStr)

const Secp256kPrecompileAddrStr = "KeccakSecp256k11111111111111111111111111111"

var Secp256kPrecompileAddr = base58.MustDecodeFromString(Secp256kPrecompileAddrStr)

const Ed25519PrecompileAddrStr = "Ed25519SigVerify111111111111111111111111111"

var Ed25519PrecompileAddr = base58.MustDecodeFromString(Ed25519PrecompileAddrStr)

var StakeProgramAddrStr = "Stake11111111111111111111111111111111111111"

var StakeProgramAddr = base58.MustDecodeFromString(StakeProgramAddrStr)

var StakeProgramConfigAddrStr = "StakeConfig11111111111111111111111111111111"

var StakeProgramConfigAddr = base58.MustDecodeFromString(StakeProgramConfigAddrStr)

var VoteProgramAddrStr = "Vote111111111111111111111111111111111111111"

var VoteProgramAddr = base58.MustDecodeFromString(VoteProgramAddrStr)

var SystemProgramAddrStr = "11111111111111111111111111111111"

var SystemProgramAddr = base58.MustDecodeFromString(SystemProgramAddrStr)

var AddressLookupTableProgramAddrStr = "AddressLookupTab1e1111111111111111111111111"

var AddressLookupTableAddr = base58.MustDecodeFromString(AddressLookupTableProgramAddrStr)

var ComputeBudgetProgramAddrStr = "ComputeBudget111111111111111111111111111111"

var ComputeBudgetProgramAddr = base58.MustDecodeFromString(ComputeBudgetProgramAddrStr)

var IsPrecompile = errors.New("IsPrecompile")

var invalidEnumValue = errors.New("invalid enum value")

func resolveNativeProgramById(programId [32]byte) (func(ctx *ExecutionCtx) error, error) {

	switch programId {
	case ConfigProgramAddr:
		return ConfigProgramExecute, nil
	case SystemProgramAddr:
		return SystemProgramExecute, nil
	case StakeProgramAddr:
		return StakeProgramExecute, nil
	case VoteProgramAddr:
		return VoteProgramExecute, nil
	case AddressLookupTableAddr:
		return AddressLookupTableExecute, nil
	case ComputeBudgetProgramAddr:
		return ComputeBudgetExecute, nil
	case BpfLoaderUpgradeableAddr:
		return BpfLoaderProgramExecute, nil
	case BpfLoader2Addr:
		return BpfLoaderProgramExecute, nil
	case Ed25519PrecompileAddr:
		return Ed25519ProgramExecute, nil
	case Secp256kPrecompileAddr:
		return Secp256k1ProgramExecute, nil
	}

	return nil, InstrErrUnsupportedProgramId
}

func verifySigner(authorized solana.PublicKey, signers []solana.PublicKey) error {
	for _, signer := range signers {
		if signer == authorized {
			return nil
		}
	}
	return InstrErrMissingRequiredSignature
}
