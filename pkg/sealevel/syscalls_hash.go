package sealevel

import (
	"crypto/sha256"
	"unsafe"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/zeebo/blake3"
	"go.firedancer.io/radiance/pkg/safemath"
	"go.firedancer.io/radiance/pkg/sbpf"
	"go.firedancer.io/radiance/pkg/sbpf/cu"
	"golang.org/x/crypto/sha3"
)

// SyscallSha256Impl is the implementation for the sol_sha256 syscall
func SyscallSha256Impl(vm sbpf.VM, valsAddr, valsLen, resultsAddr uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	if valsLen > CUSha256MaxSlices {
		err = SyscallErrTooManySlices
		return
	}

	cuOut = cu.ConsumeLowerBound(cuIn, CUSha256BaseCost, 0)
	if cuOut < 0 {
		return
	}

	hashResult, err := vm.Translate(resultsAddr, 32, true)
	if err != nil {
		return
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
			return
		}

		var data []byte
		var idx uint64

		for count := uint64(0); count < valsLen; count++ {
			dataPtr := *(*uint64)(unsafe.Pointer(&vals[idx]))
			dataSize := *(*uint64)(unsafe.Pointer(&vals[idx+8]))
			idx += 16

			data, err = vm.Translate(dataPtr, dataSize, false)
			if err != nil {
				return
			}

			cost := safemath.SaturatingMulU64(CUSha256ByteCost, dataSize) / 2
			if CUMemOpBaseCost > cost {
				cost = CUMemOpBaseCost
			}
			cuOut = cu.ConsumeLowerBound(cuOut, int(cost), 0)
			if cuOut < 0 {
				return
			}
			hasher.Write(data)
		}
	}
	copy(hashResult[:], hasher.Sum(nil))
	return
}

var SyscallSha256 = sbpf.SyscallFunc3(SyscallSha256Impl)

// SyscallKeccak256Impl is the implementation for the sol_keccak256 syscall
func SyscallKeccak256Impl(vm sbpf.VM, valsAddr, valsLen, resultsAddr uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	if valsLen > CUSha256MaxSlices {
		err = SyscallErrTooManySlices
		return
	}

	cuOut = cu.ConsumeLowerBound(cuIn, CUSha256BaseCost, 0)
	if cuOut < 0 {
		return
	}

	hashResult, err := vm.Translate(resultsAddr, 32, true)
	if err != nil {
		return
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
			return
		}

		var data []byte
		var idx uint64

		for count := uint64(0); count < valsLen; count++ {
			dataPtr := *(*uint64)(unsafe.Pointer(&vals[idx]))
			dataSize := *(*uint64)(unsafe.Pointer(&vals[idx+8]))
			idx += 16

			data, err = vm.Translate(dataPtr, dataSize, false)
			if err != nil {
				return
			}

			cost := safemath.SaturatingMulU64(CUSha256ByteCost, dataSize) / 2
			if CUMemOpBaseCost > cost {
				cost = CUMemOpBaseCost
			}
			cuOut = cu.ConsumeLowerBound(cuOut, int(cost), 0)
			if cuOut < 0 {
				return
			}
			hasher.Write(data)
		}
	}
	copy(hashResult[:], hasher.Sum(nil))
	return
}

var SyscallKeccak256 = sbpf.SyscallFunc3(SyscallKeccak256Impl)

// SyscallBlake3Impl is the implementation for the sol_blake3 syscall
func SyscallBlake3Impl(vm sbpf.VM, valsAddr, valsLen, resultsAddr uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	if valsLen > CUSha256MaxSlices {
		err = SyscallErrTooManySlices
		return
	}

	cuOut = cu.ConsumeLowerBound(cuIn, CUSha256BaseCost, 0)
	if cuOut < 0 {
		return
	}

	hashResult, err := vm.Translate(resultsAddr, 32, true)
	if err != nil {
		return
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
			return
		}

		var data []byte
		var idx uint64

		for count := uint64(0); count < valsLen; count++ {
			dataPtr := *(*uint64)(unsafe.Pointer(&vals[idx]))
			dataSize := *(*uint64)(unsafe.Pointer(&vals[idx+8]))
			idx += 16

			data, err = vm.Translate(dataPtr, dataSize, false)
			if err != nil {
				return
			}

			cost := safemath.SaturatingMulU64(CUSha256ByteCost, dataSize) / 2
			if CUMemOpBaseCost > cost {
				cost = CUMemOpBaseCost
			}
			cuOut = cu.ConsumeLowerBound(cuOut, int(cost), 0)
			if cuOut < 0 {
				return
			}
			hasher.Write(data)
		}
	}
	copy(hashResult[:], hasher.Sum(nil))
	return
}

var SyscallBlake3 = sbpf.SyscallFunc3(SyscallBlake3Impl)

// SyscallSecp256k1Recover is an implementation of the sol_secp256k1_recover syscall
func SyscallSecp256k1RecoverImpl(vm sbpf.VM, hashAddr, recoveryIdVal, signatureAddr, resultAddr uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	cuOut, err = cu.ConsumeComputeMeter(cuIn, CUSecP256k1RecoverCost)
	if err != nil {
		return
	}

	hash, err := vm.Translate(hashAddr, 32, false)
	if err != nil {
		return
	}

	signature, err := vm.Translate(signatureAddr, 64, false)
	if err != nil {
		return
	}

	recoverResult, err := vm.Translate(resultAddr, 64, true)
	if err != nil {
		return
	}

	// the Labs validator calls `libsecp256k1::Message::parse_slice` and returns the error
	// `Secp256k1RecoverError::InvalidHash` if the parse fails, but we don't need to do that
	// because all the `parse_slice` function checks for is len(hash) == 32, which is always
	// the case.

	// check for invalid recovery ID
	if recoveryIdVal >= 4 {
		r0 = 2 // Secp256k1RecoverError::InvalidHash
		return
	}

	err = parseAndValidateSignature(signature)
	if err != nil {
		r0 = 3 // Secp256k1RecoverError::InvalidSignature
		return
	}

	sigAndRecoveryId := make([]byte, 65)
	copy(sigAndRecoveryId, signature)
	sigAndRecoveryId[64] = byte(recoveryIdVal)

	recoveredPubKey, err := secp256k1.RecoverPubkey(hash, sigAndRecoveryId)
	if err != nil {
		r0 = 3 // Secp256k1RecoverError::InvalidSignature
		return
	}

	copy(recoverResult, recoveredPubKey)
	r0 = 0
	return
}

var SyscallSecp256k1Recover = sbpf.SyscallFunc4(SyscallSecp256k1RecoverImpl)
