package sealevel

import (
	"errors"

	"go.firedancer.io/radiance/pkg/base58"
)

const BpfLoaderDeprecatedAddrStr = "BPFLoader1111111111111111111111111111111111"

var BpfLoaderDeprecatedAddr = base58.MustDecodeFromString("BPFLoader1111111111111111111111111111111111")

const NativeLoaderAddrStr = "NativeLoader1111111111111111111111111111111"

var NativeLoaderAddr = base58.MustDecodeFromString(NativeLoaderAddrStr)

const ConfigProgramAddrStr = "Config1111111111111111111111111111111111111"

var ConfigProgramAddr = base58.MustDecodeFromString(ConfigProgramAddrStr)

const Secp256kPrecompileAddrStr = "KeccakSecp256k11111111111111111111111111111"

var Secp256kPrecompileAddr = base58.MustDecodeFromString(Secp256kPrecompileAddrStr)

const Ed25519PrecompileAddrStr = "KeccakSecp256k11111111111111111111111111111"

var Ed25519PrecompileAddr = base58.MustDecodeFromString(Ed25519PrecompileAddrStr)

var IsPrecompile = errors.New("IsPrecompile")

func ResolveNativeProgramById(programId [32]byte) (func(ctx *ExecutionCtx) error, error) {

	switch programId {
	case ConfigProgramAddr:
		return ConfigProgramExecute, nil
	case Secp256kPrecompileAddr:
		return nil, IsPrecompile
	case Ed25519PrecompileAddr:
		return nil, IsPrecompile
	}

	return nil, InstrErrUnsupportedProgramId
}
