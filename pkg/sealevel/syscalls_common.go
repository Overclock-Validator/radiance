package sealevel

import (
	"errors"
	"math"

	"go.firedancer.io/radiance/pkg/cu"
)

func isNonOverlapping(src, srcLen, dst, dstLen uint64) bool {
	if src > dst {
		return src-dst >= dstLen
	} else {
		return dst-src >= srcLen
	}
}

var genericSyscallErr = errors.New("syscallError")

func syscallErrGeneric() (uint64, error) {
	return math.MaxUint64, genericSyscallErr
}

func syscallErrCustom(msg string) (uint64, error) {
	return math.MaxUint64, errors.New(msg)
}

func syscallErr(err error) (uint64, error) {
	return math.MaxUint64, err
}

func syscallCuErr() (uint64, error) {
	return math.MaxUint64, cu.ErrComputeExceeded
}

func syscallSuccess(result uint64) (uint64, error) {
	return result, nil
}
