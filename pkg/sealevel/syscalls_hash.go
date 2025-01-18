package sealevel

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/Overclock-Validator/mithril/pkg/sbpf"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/sha3"
	"k8s.io/klog/v2"
)

// SyscallSha256Impl is the implementation for the sol_sha256 syscall
func SyscallSha256Impl(vm sbpf.VM, valsAddr, valsLen, resultsAddr uint64) (uint64, error) {
	klog.Infof("SyscallSha256Impl")

	if valsLen > CUSha256MaxSlices {
		return syscallErr(SyscallErrTooManySlices)
	}

	execCtx := executionCtx(vm)
	err := execCtx.ComputeMeter.Consume(CUSha256BaseCost)
	if err != nil {
		return syscallCuErr()
	}

	hashResult, err := vm.Translate(resultsAddr, 32, true)
	if err != nil {
		return syscallErr(err)
	}

	hasher := sha256.New()
	if valsLen > 0 {
		var vals []byte

		// The data at 'valsAddr' consists of an array of 'slice references', which consists
		// of: [ptr (u64)] [size (u64)], hence 16 bytes for each of the slice references that
		// refers to an input value to hash.
		// Safety: valsLen*16 cannot overflow because of the check versus CUSha256MaxSlices above
		vals, err = vm.Translate(valsAddr, valsLen*16, false)
		if err != nil {
			return syscallErr(err)
		}

		var data []byte
		reader := bytes.NewReader(vals)

		for count := uint64(0); count < valsLen; count++ {

			var vec VectorDescrC
			err = vec.Unmarshal(reader)
			if err != nil {
				return syscallErr(err)
			}

			data, err = vm.Translate(vec.Addr, vec.Len, false)
			if err != nil {
				return syscallErr(err)
			}

			cost := max(vec.Len/2, CUMemOpBaseCost)
			err = execCtx.ComputeMeter.Consume(cost)
			if err != nil {
				return syscallCuErr()
			}

			hasher.Write(data)
		}
	}
	copy(hashResult[:], hasher.Sum(nil))
	return syscallSuccess(0)
}

var SyscallSha256 = sbpf.SyscallFunc3(SyscallSha256Impl)

// SyscallKeccak256Impl is the implementation for the sol_keccak256 syscall
func SyscallKeccak256Impl(vm sbpf.VM, valsAddr, valsLen, resultsAddr uint64) (uint64, error) {
	klog.Infof("SyscallKeccak256")

	if valsLen > CUSha256MaxSlices {
		return syscallErr(SyscallErrTooManySlices)
	}

	execCtx := executionCtx(vm)
	err := execCtx.ComputeMeter.Consume(CUSha256BaseCost)
	if err != nil {
		return syscallCuErr()
	}

	hashResult, err := vm.Translate(resultsAddr, 32, true)
	if err != nil {
		return syscallErr(err)
	}

	hasher := sha3.NewLegacyKeccak256()
	if valsLen > 0 {
		var vals []byte

		// The data at 'valsAddr' consists of an array of 'slice references', which consists
		// of: [ptr (u64)] [size (u64)], hence 16 bytes for each of the slice references that
		// refers to an input value to hash.
		// Safety: valsLen*16 cannot overflow because of the check versus CUSha256MaxSlices above
		vals, err = vm.Translate(valsAddr, valsLen*16, false)
		if err != nil {
			return syscallErr(err)
		}

		var data []byte
		reader := bytes.NewReader(vals)

		for count := uint64(0); count < valsLen; count++ {
			var vec VectorDescrC
			err = vec.Unmarshal(reader)
			if err != nil {
				return syscallErr(err)
			}

			data, err = vm.Translate(vec.Addr, vec.Len, false)
			if err != nil {
				return syscallErr(err)
			}

			cost := max(CUMemOpBaseCost, vec.Len/2)
			err = execCtx.ComputeMeter.Consume(cost)
			if err != nil {
				return syscallCuErr()
			}

			hasher.Write(data)
		}
	}
	copy(hashResult[:], hasher.Sum(nil))
	return syscallSuccess(0)
}

var SyscallKeccak256 = sbpf.SyscallFunc3(SyscallKeccak256Impl)

// SyscallBlake3Impl is the implementation for the sol_blake3 syscall
func SyscallBlake3Impl(vm sbpf.VM, valsAddr, valsLen, resultsAddr uint64) (uint64, error) {
	klog.Infof("SyscallBlake3")

	if valsLen > CUSha256MaxSlices {
		return syscallErr(SyscallErrTooManySlices)
	}

	execCtx := executionCtx(vm)
	err := execCtx.ComputeMeter.Consume(CUSha256BaseCost)
	if err != nil {
		return syscallCuErr()
	}

	hashResult, err := vm.Translate(resultsAddr, 32, true)
	if err != nil {
		return syscallErr(err)
	}

	hasher := blake3.New()
	if valsLen > 0 {
		var vals []byte

		// The data at 'valsAddr' consists of an array of 'slice references', which consists
		// of: [ptr (u64)] [size (u64)], hence 16 bytes for each of the slice references that
		// refers to an input value to hash.
		// Safety: valsLen*16 cannot overflow because of the check versus CUSha256MaxSlices above
		vals, err = vm.Translate(valsAddr, valsLen*16, false)
		if err != nil {
			return syscallErr(err)
		}

		var data []byte
		reader := bytes.NewReader(vals)

		for count := uint64(0); count < valsLen; count++ {
			var vec VectorDescrC
			err = vec.Unmarshal(reader)
			if err != nil {
				return syscallErr(err)
			}

			data, err = vm.Translate(vec.Addr, vec.Len, false)
			if err != nil {
				return syscallErr(err)
			}

			cost := max(vec.Len/2, CUMemOpBaseCost)
			err = execCtx.ComputeMeter.Consume(cost)
			if err != nil {
				return syscallCuErr()
			}

			hasher.Write(data)
		}
	}
	copy(hashResult[:], hasher.Sum(nil))
	return syscallSuccess(0)
}

var SyscallBlake3 = sbpf.SyscallFunc3(SyscallBlake3Impl)

// SyscallSecp256k1Recover is an implementation of the sol_secp256k1_recover syscall
func SyscallSecp256k1RecoverImpl(vm sbpf.VM, hashAddr, recoveryIdVal, signatureAddr, resultAddr uint64) (uint64, error) {
	klog.Infof("SyscallSecp256k1Recover")

	execCtx := executionCtx(vm)
	err := execCtx.ComputeMeter.Consume(CUSecP256k1RecoverCost)
	if err != nil {
		return syscallCuErr()
	}

	hash, err := vm.Translate(hashAddr, 32, false)
	if err != nil {
		return syscallErr(err)
	}

	signature, err := vm.Translate(signatureAddr, 64, false)
	if err != nil {
		return syscallErr(err)
	}

	recoverResult, err := vm.Translate(resultAddr, 64, true)
	if err != nil {
		return syscallErr(err)
	}

	// the Labs validator calls `libsecp256k1::Message::parse_slice` and returns the error
	// `Secp256k1RecoverError::InvalidHash` if the parse fails, but we don't need to do that
	// because all the `parse_slice` function checks for is len(hash) == 32, which is always
	// the case.

	// check for invalid recovery ID
	if recoveryIdVal >= 4 {
		return syscallSuccess(2) // Secp256k1RecoverError::InvalidRecoveryId
	}

	err = parseAndValidateSignature(signature)
	if err != nil {
		return syscallSuccess(3) // Secp256k1RecoverError::InvalidSignature
	}

	sigAndRecoveryId := make([]byte, 65)
	copy(sigAndRecoveryId, signature)
	sigAndRecoveryId[64] = byte(recoveryIdVal)

	recoveredPubKey, err := secp256k1.RecoverPubkey(hash, sigAndRecoveryId)
	if err != nil {
		return syscallSuccess(3) // Secp256k1RecoverError::InvalidSignature
	}

	copy(recoverResult, recoveredPubKey[1:])
	return syscallSuccess(0)
}

var SyscallSecp256k1Recover = sbpf.SyscallFunc4(SyscallSecp256k1RecoverImpl)

const PoseidonCostCoefficientA = 61
const PoseidonCostCoefficientC = 542

func SwapEndianness(xs []byte) []byte {
	ys := make([]byte, len(xs))
	for i, b := range xs {
		ys[len(xs)-1-i] = b
	}
	return ys
}

func PoseidonHash(input [][]byte, isBigEndian bool) ([]byte, error) {
	inputBigInts := make([]*big.Int, 0)

	for _, inputSlice := range input {
		if len(inputSlice) > 32 {
			return nil, fmt.Errorf("input too long")
		}
		bigInt := new(big.Int).SetBytes(inputSlice)
		inputBigInts = append(inputBigInts, bigInt)
	}

	initState := new(big.Int)
	output, err := poseidon.HashWithState(inputBigInts, initState)
	if err != nil {
		return nil, fmt.Errorf("hashing error")
	}

	hashBytes := output.Bytes()

	if len(hashBytes) == 31 {
		fixed := make([]byte, 32)
		copy(fixed[1:], hashBytes)
		hashBytes = fixed
	}

	if !isBigEndian {
		hashBytes = SwapEndianness(hashBytes)
	}

	return hashBytes, nil
}

func SyscallPoseidonImpl(vm sbpf.VM, parameters, endianness, valsAddr, valsLen, resultAddr uint64) (uint64, error) {
	klog.Infof("SyscallPoseidon")

	execCtx := executionCtx(vm)

	if parameters != 0 {
		return syscallErrCustom("PoseidonSyscallError::InvalidParameters")
	}

	if endianness != 0 && endianness != 1 {
		return syscallErrCustom("PoseidonSyscallError::InvalidEndianness")
	}

	if valsLen > 12 {
		klog.Infof("Poseidon hashing %d sequences is not supported", valsLen)
		return syscallErrCustom("PoseidonSyscallError::InvalidLength")
	}

	// no need to use saturating math here; this can't overflow anyway, as per the valsLen check above
	cost := (valsLen * valsLen * PoseidonCostCoefficientA) + PoseidonCostCoefficientC

	err := execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return syscallCuErr()
	}

	hashResult, err := vm.Translate(resultAddr, 32, true)
	if err != nil {
		return syscallErr(err)
	}

	if valsLen == 0 {
		return syscallSuccess(1)
	}

	inputBytes, err := vm.Translate(valsAddr, valsLen*16, false)
	if err != nil {
		return syscallErr(err)
	}

	inputs := make([][]byte, 0)
	reader := bytes.NewReader(inputBytes)

	for count := uint64(0); count < valsLen; count++ {
		var vec VectorDescrC
		vec.Unmarshal(reader)
		inputSlice, err := vm.Translate(vec.Addr, vec.Len, false)
		if err != nil {
			return syscallErr(err)
		}
		inputs = append(inputs, inputSlice)
	}

	isBigEndian := endianness == 0

	hash, err := PoseidonHash(inputs, isBigEndian)
	if err != nil {
		return syscallSuccess(1)
	}

	copy(hashResult, hash)
	return syscallSuccess(0)
}

var SyscallPoseidon = sbpf.SyscallFunc5(SyscallPoseidonImpl)
