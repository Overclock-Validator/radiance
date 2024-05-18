package sealevel

import (
	"errors"

	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/base58"
)

const BpfLoaderUpgradeableAddrStr = "BPFLoaderUpgradeab1e11111111111111111111111"

var BpfLoaderUpgradeableAddr = base58.MustDecodeFromString(BpfLoaderUpgradeableAddrStr)

const BpfLoaderAddrStr = "BPFLoader2111111111111111111111111111111111"

var BpfLoaderAddr = base58.MustDecodeFromString(BpfLoaderAddrStr)

const BpfLoaderDeprecatedAddrStr = "BPFLoader1111111111111111111111111111111111"

var BpfLoaderDeprecatedAddr = base58.MustDecodeFromString(BpfLoaderDeprecatedAddrStr)

const NativeLoaderAddrStr = "NativeLoader1111111111111111111111111111111"

var NativeLoaderAddr = base58.MustDecodeFromString(NativeLoaderAddrStr)

const ConfigProgramAddrStr = "Config1111111111111111111111111111111111111"

var ConfigProgramAddr = base58.MustDecodeFromString(ConfigProgramAddrStr)

const Secp256kPrecompileAddrStr = "KeccakSecp256k11111111111111111111111111111"

var Secp256kPrecompileAddr = base58.MustDecodeFromString(Secp256kPrecompileAddrStr)

const Ed25519PrecompileAddrStr = "KeccakSecp256k11111111111111111111111111111"

var Ed25519PrecompileAddr = base58.MustDecodeFromString(Ed25519PrecompileAddrStr)

var StakeProgramAddrStr = "Stake11111111111111111111111111111111111111"

var StakeProgramAddr = base58.MustDecodeFromString(StakeProgramAddrStr)

var StakeProgramConfigAddrStr = "StakeConfig11111111111111111111111111111111"

var StakeProgramConfigAddr = base58.MustDecodeFromString(StakeProgramConfigAddrStr)

var VoteProgramAddrStr = "Vote111111111111111111111111111111111111111"

var VoteProgramAddr = base58.MustDecodeFromString(VoteProgramAddrStr)

var SystemProgramAddrStr = "11111111111111111111111111111111"

var SystemProgramAddr = base58.MustDecodeFromString(SystemProgramAddrStr)

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
	case Secp256kPrecompileAddr:
		return nil, IsPrecompile
	case Ed25519PrecompileAddr:
		return nil, IsPrecompile
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
