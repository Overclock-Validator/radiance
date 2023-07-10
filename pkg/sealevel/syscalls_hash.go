package sealevel

import (
	"crypto/sha256"
	"unsafe"

	"github.com/zeebo/blake3"
	"go.firedancer.io/radiance/pkg/safemath"
	"go.firedancer.io/radiance/pkg/sbpf"
	"go.firedancer.io/radiance/pkg/sbpf/cu"
)

// SyscallSha256Impl is the implementation for the sol_sha256 syscall
func SyscallSha256Impl(vm sbpf.VM, valsAddr, valsLen, resultsAddr uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	if valsLen > CUSha256MaxSlices {
		err = TooManySlices
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

			cost := safemath.SaturatingMulU64(CuSha256ByteCost, dataSize) / 2
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

// SyscallBlake3Impl is the implementation for the sol_blake3 syscall
func SyscallBlake3Impl(vm sbpf.VM, valsAddr, valsLen, resultsAddr uint64, cuIn int) (r0 uint64, cuOut int, err error) {
	if valsLen > CUSha256MaxSlices {
		err = TooManySlices
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

			cost := safemath.SaturatingMulU64(CuSha256ByteCost, dataSize) / 2
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
