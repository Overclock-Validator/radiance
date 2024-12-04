package sealevel

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/Overclock-Validator/mithril/pkg/safemath"
	"github.com/Overclock-Validator/mithril/pkg/sbpf"
	"github.com/gagliardetto/solana-go"
	"k8s.io/klog/v2"
)

func SyscallLogImpl(vm sbpf.VM, ptr, strlen uint64) (uint64, error) {
	klog.Infof("SyscallLog")

	execCtx := executionCtx(vm)

	cost := max(CUSyscallBaseCost, strlen)
	err := execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return syscallCuErr()
	}

	buf := make([]byte, strlen)
	if err = vm.Read(ptr, buf); err != nil {
		return syscallErr(err)
	}
	execCtx.Log.Log("Program log: " + string(buf))
	return syscallSuccess(0)
}

var SyscallLog = sbpf.SyscallFunc2(SyscallLogImpl)

func SyscallLog64Impl(vm sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	klog.Infof("SyscallLog64")

	execCtx := executionCtx(vm)
	err := execCtx.ComputeMeter.Consume(CULog64Units)
	if err != nil {
		return syscallCuErr()
	}

	msg := fmt.Sprintf("Program log: %#x, %#x, %#x, %#x, %#x\n", r1, r2, r3, r4, r5)
	execCtx.Log.Log(msg)
	return syscallSuccess(0)
}

var SyscallLog64 = sbpf.SyscallFunc5(SyscallLog64Impl)

func SyscallLogCUsImpl(vm sbpf.VM) (uint64, error) {
	klog.Infof("SyscallLogCUs")

	execCtx := executionCtx(vm)
	err := execCtx.ComputeMeter.Consume(CUSyscallBaseCost)
	if err != nil {
		return syscallCuErr()
	}

	msg := fmt.Sprintf("Program consumption: %d units remaining", execCtx.ComputeMeter.Remaining())
	execCtx.Log.Log(msg)
	return syscallSuccess(0)
}

var SyscallLogCUs = sbpf.SyscallFunc0(SyscallLogCUsImpl)

func SyscallLogPubkeyImpl(vm sbpf.VM, pubkeyAddr uint64) (uint64, error) {
	klog.Infof("SyscallLogPubkey")

	execCtx := executionCtx(vm)
	err := execCtx.ComputeMeter.Consume(CULogPubkeyUnits)
	if err != nil {
		return syscallCuErr()
	}

	var pubkey solana.PublicKey
	if err = vm.Read(pubkeyAddr, pubkey[:]); err != nil {
		return syscallErr(err)
	}

	execCtx.Log.Log("Program log: " + pubkey.String())
	return syscallSuccess(0)
}

var SyscallLogPubkey = sbpf.SyscallFunc1(SyscallLogPubkeyImpl)

func SyscallLogDataImpl(vm sbpf.VM, addr uint64, len uint64) (uint64, error) {
	klog.Infof("SyscallLogData")

	execCtx := executionCtx(vm)
	err := execCtx.ComputeMeter.Consume(CUSyscallBaseCost)
	if err != nil {
		return syscallCuErr()
	}

	size, err := safemath.CheckedMulU64(len, 16)
	if err != nil {
		return syscallErr(err)
	}

	mem, err := vm.Translate(addr, size, false)
	if err != nil {
		return syscallErr(err)
	}

	err = execCtx.ComputeMeter.Consume(safemath.SaturatingMulU64(len, CUSyscallBaseCost))
	if err != nil {
		return syscallCuErr()
	}

	msg := ""

	var data []byte
	reader := bytes.NewReader(mem)

	for count := uint64(0); count < len; count++ {
		var vec VectorDescrC
		err = vec.Unmarshal(reader)
		if err != nil {
			return syscallErr(err)
		}

		err = execCtx.ComputeMeter.Consume(vec.Len)
		if err != nil {
			return syscallCuErr()
		}

		data, err = vm.Translate(vec.Addr, vec.Len, false)
		if err != nil {
			return syscallErr(err)
		}
		encodedStr := base64.StdEncoding.EncodeToString(data)

		msg += fmt.Sprintf("%s ", encodedStr)
	}

	execCtx.Log.Log("Program log: " + msg)

	return syscallSuccess(0)
}

var SyscallLogData = sbpf.SyscallFunc2(SyscallLogDataImpl)
