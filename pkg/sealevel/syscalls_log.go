package sealevel

import (
	"encoding/base64"
	"fmt"
	"unsafe"

	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/safemath"
	"go.firedancer.io/radiance/pkg/sbpf"
)

func SyscallLogImpl(vm sbpf.VM, ptr, strlen uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)

	var cost uint64
	if strlen > CUSyscallBaseCost {
		cost = strlen
	} else {
		cost = CUSyscallBaseCost
	}

	err = execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return
	}

	buf := make([]byte, strlen)
	if err = vm.Read(ptr, buf); err != nil {
		return
	}
	execCtx.Log.Log("Program log: " + string(buf))
	return
}

var SyscallLog = sbpf.SyscallFunc2(SyscallLogImpl)

func SyscallLog64Impl(vm sbpf.VM, r1, r2, r3, r4, r5 uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = execCtx.ComputeMeter.Consume(CULog64Units)
	if err != nil {
		return
	}

	msg := fmt.Sprintf("Program log: %#x, %#x, %#x, %#x, %#x\n", r1, r2, r3, r4, r5)
	execCtx.Log.Log(msg)
	return
}

var SyscallLog64 = sbpf.SyscallFunc5(SyscallLog64Impl)

func SyscallLogCUsImpl(vm sbpf.VM) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = execCtx.ComputeMeter.Consume(CUSyscallBaseCost)
	if err != nil {
		return
	}

	msg := fmt.Sprintf("Program consumption: %d units remaining", execCtx.ComputeMeter.Remaining())
	execCtx.Log.Log(msg)
	return
}

var SyscallLogCUs = sbpf.SyscallFunc0(SyscallLogCUsImpl)

func SyscallLogPubkeyImpl(vm sbpf.VM, pubkeyAddr uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = execCtx.ComputeMeter.Consume(CULogPubkeyUnits)
	if err != nil {
		return
	}

	// TODO alignment check
	var pubkey solana.PublicKey
	if err = vm.Read(pubkeyAddr, pubkey[:]); err != nil {
		return
	}

	execCtx.Log.Log("Program log: " + pubkey.String())
	return
}

var SyscallLogPubkey = sbpf.SyscallFunc1(SyscallLogPubkeyImpl)

func SyscallLogDataImpl(vm sbpf.VM, addr uint64, len uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = execCtx.ComputeMeter.Consume(CUSyscallBaseCost)
	if err != nil {
		return
	}

	size, err := safemath.CheckedMulU64(len, 16)
	if err != nil {
		return
	}

	mem, err := vm.Translate(addr, size, false)
	if err != nil {
		return
	}

	msg := ""
	totalSize := uint64(0)

	var data []byte
	var idx uint64

	for count := uint64(0); count < len; count++ {
		dataPtr := *(*uint64)(unsafe.Pointer(&mem[idx]))
		dataSize := *(*uint64)(unsafe.Pointer(&mem[idx+8]))
		idx += 16

		totalSize = safemath.SaturatingAddU64(totalSize, dataSize)

		data, err = vm.Translate(dataPtr, dataSize, false)
		if err != nil {
			return
		}
		encodedStr := base64.StdEncoding.EncodeToString(data)
		if count != len-1 {
			msg += fmt.Sprintf(" ")
		}

		msg += fmt.Sprintf("%s", encodedStr)
	}

	err = execCtx.ComputeMeter.Consume(totalSize)
	if err != nil {
		return
	}

	execCtx.Log.Log("Program log: " + msg)

	r0 = 0
	return
}

var SyscallLogData = sbpf.SyscallFunc2(SyscallLogDataImpl)
