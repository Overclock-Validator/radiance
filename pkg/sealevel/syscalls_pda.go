package sealevel

import (
	"bytes"

	"github.com/Overclock-Validator/mithril/pkg/sbpf"
	"github.com/Overclock-Validator/mithril/pkg/solana"
	"github.com/ethereum/go-ethereum/common/math"
	"k8s.io/klog/v2"
)

const MaxSeeds = 16
const MaxSeedLen = 32

func translateAndValidateSeeds(vm sbpf.VM, seedsAddr, seedsLen uint64) ([][]byte, error) {
	if seedsLen > MaxSeeds {
		return nil, SyscallErrMaxSeedLengthExceeded
	}

	seedsData, err := vm.Translate(seedsAddr, seedsLen*16, false)
	if err != nil {
		return nil, err
	}

	var data []byte
	reader := bytes.NewReader(seedsData)
	seedsRet := make([][]byte, 0)

	for count := uint64(0); count < seedsLen; count++ {
		var vec VectorDescrC
		err = vec.Unmarshal(reader)
		if err != nil {
			return nil, err
		}

		if vec.Len > MaxSeedLen {
			return nil, SyscallErrMaxSeedLengthExceeded
		}

		data, err = vm.Translate(vec.Addr, vec.Len, false)
		if err != nil {
			return nil, err
		}
		seedsRet = append(seedsRet, data)
	}

	return seedsRet, nil
}

func SyscallCreateProgramAddressImpl(vm sbpf.VM, seedsAddr, seedsLen, programIdAddr, addressAddr uint64) (uint64, error) {
	klog.Infof("SyscallCreateProgramAddress")

	execCtx := executionCtx(vm)
	origCu := execCtx.ComputeMeter.Remaining()
	err := execCtx.ComputeMeter.Consume(CUCreateProgramAddressUnits)
	if err != nil {
		klog.Infof("******** ran out of CUs in SyscallCreateProgramAddress")
		return syscallCuErr()
	}

	seeds, err := translateAndValidateSeeds(vm, seedsAddr, seedsLen)
	if err != nil {
		return syscallErr(err)
	}

	programId, err := vm.Translate(programIdAddr, 32, false)
	if err != nil {
		return syscallErr(err)
	}

	newAddress, err := solana.CreateProgramAddressBytes(seeds, programId)
	if err != nil {
		return syscallSuccess(1)
	}

	address, err := vm.Translate(addressAddr, 32, true)
	if err != nil {
		return syscallErr(err)
	}

	used := origCu - execCtx.ComputeMeter.Remaining()
	klog.Infof("******** SyscallCreateProgramAddress used %d CUs", used)

	copy(address, newAddress)
	return syscallSuccess(0)
}

var SyscallCreateProgramAddress = sbpf.SyscallFunc4(SyscallCreateProgramAddressImpl)

func SyscallTryFindProgramAddressImpl(vm sbpf.VM, seedsAddr, seedsLen, programIdAddr, addressAddr, bumpSeedAddr uint64) (uint64, error) {
	klog.Infof("SyscallTryFindProgramAddress")

	execCtx := executionCtx(vm)
	origCu := execCtx.ComputeMeter.Remaining()

	err := execCtx.ComputeMeter.Consume(CUCreateProgramAddressUnits)
	if err != nil {
		return syscallCuErr()
	}

	seeds, err := translateAndValidateSeeds(vm, seedsAddr, seedsLen)
	if err != nil {
		return syscallErr(err)
	}

	programId, err := vm.Translate(programIdAddr, 32, false)
	if err != nil {
		return syscallErr(err)
	}

	for bumpSeed := uint8(math.MaxUint8); bumpSeed > 0; bumpSeed-- {
		seedsWithBump := make([][]byte, 0)
		for _, seed := range seeds {
			seedsWithBump = append(seedsWithBump, seed)
		}
		seedsWithBump = append(seedsWithBump, []byte{bumpSeed})

		var newAddress []byte
		newAddress, err = solana.CreateProgramAddressBytes(seedsWithBump, programId)
		if err == nil {
			var bumpSeedOut []byte
			bumpSeedOut, err = vm.Translate(bumpSeedAddr, 1, true)
			if err != nil {
				return syscallErr(err)
			}
			var addressOut []byte
			addressOut, err = vm.Translate(addressAddr, 32, true)
			if err != nil {
				return syscallErr(err)
			}
			if !isNonOverlapping(bumpSeedAddr, 1, addressAddr, 32) {
				err = SyscallErrCopyOverlapping
				return syscallErr(err)
			}
			bumpSeedOut[0] = bumpSeed
			copy(addressOut, newAddress)

			used := origCu - execCtx.ComputeMeter.Remaining()
			klog.Infof("******** SyscallTryFindProgramAddress used %d CUs. bumpSeed = %d", used, bumpSeed)

			// address found
			return syscallSuccess(0)
		}
		err = execCtx.ComputeMeter.Consume(CUCreateProgramAddressUnits)
		if err != nil {
			klog.Infof("******** ran out of CUs in TryFindProgramAddress")
			return syscallCuErr()
		}
	}

	// address not found
	return syscallSuccess(1)
}

var SyscallTryFindProgramAddress = sbpf.SyscallFunc5(SyscallTryFindProgramAddressImpl)
