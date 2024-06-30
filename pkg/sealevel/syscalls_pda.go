package sealevel

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common/math"
	"go.firedancer.io/radiance/pkg/sbpf"
	"go.firedancer.io/radiance/pkg/solana"
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

func SyscallCreateProgramAddressImpl(vm sbpf.VM, seedsAddr, seedsLen, programIdAddr, addressAddr uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = execCtx.ComputeMeter.Consume(CUCreateProgramAddressUnits)
	if err != nil {
		return
	}

	seeds, err := translateAndValidateSeeds(vm, seedsAddr, seedsLen)
	if err != nil {
		return
	}

	programId, err := vm.Translate(programIdAddr, 32, false)
	if err != nil {
		return
	}

	newAddress, err := solana.CreateProgramAddressBytes(seeds, programId)
	if err != nil {
		return 1, nil
	}

	address, err := vm.Translate(addressAddr, 32, true)
	if err != nil {
		return
	}

	copy(address, newAddress)
	return 0, nil
}

var SyscallCreateProgramAddress = sbpf.SyscallFunc4(SyscallCreateProgramAddressImpl)

func SyscallTryFindProgramAddressImpl(vm sbpf.VM, seedsAddr, seedsLen, programIdAddr, addressAddr, bumpSeedAddr uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = execCtx.ComputeMeter.Consume(CUCreateProgramAddressUnits)
	if err != nil {
		return
	}

	seeds, err := translateAndValidateSeeds(vm, seedsAddr, seedsLen)
	if err != nil {
		return
	}

	programId, err := vm.Translate(programIdAddr, 32, false)
	if err != nil {
		return
	}

	for bumpSeed := uint8(math.MaxUint8); bumpSeed > 0; bumpSeed-- {
		seedsWithBump := make([][]byte, len(seeds))
		for i := range seeds {
			seedsWithBump[i] = make([]byte, len(seeds[i]))
			copy(seedsWithBump[i], seeds[i])
		}
		seedsWithBump = append(seedsWithBump, []byte{bumpSeed})

		var newAddress []byte
		newAddress, err = solana.CreateProgramAddressBytes(seedsWithBump, programId)
		if err == nil {
			var bumpSeedOut []byte
			bumpSeedOut, err = vm.Translate(bumpSeedAddr, 1, true)
			if err != nil {
				return
			}
			var addressOut []byte
			addressOut, err = vm.Translate(addressAddr, 32, true)
			if err != nil {
				return
			}
			if !isNonOverlapping(bumpSeedAddr, 1, addressAddr, 32) {
				err = SyscallErrCopyOverlapping
				return
			}
			bumpSeedOut[0] = bumpSeed
			copy(addressOut, newAddress)
			return 0, nil
		}
		err = execCtx.ComputeMeter.Consume(CUCreateProgramAddressUnits)
		if err != nil {
			return
		}
	}

	return 1, nil
}

var SyscallTryFindProgramAddress = sbpf.SyscallFunc5(SyscallTryFindProgramAddressImpl)
