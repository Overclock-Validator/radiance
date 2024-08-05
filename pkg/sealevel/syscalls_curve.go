package sealevel

import (
	"filippo.io/edwards25519"
	"github.com/bwesterb/go-ristretto"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/sbpf"
)

const curve25519Edwards = 0
const curve25519Ristretto = 1

func SyscallCurveValidatePointImpl(vm sbpf.VM, curveId, pointAddr uint64) (uint64, error) {
	execCtx := executionCtx(vm)

	switch curveId {
	case curve25519Edwards:
		{
			err := execCtx.ComputeMeter.Consume(CUCurve25519EdwardsValidatePointCost)
			if err != nil {
				return syscallCuErr()
			}

			pointBytes, err := vm.Translate(pointAddr, 32, false)
			if err != nil {
				return syscallErr(err)
			}

			var point edwards25519.Point
			_, err = point.SetBytes(pointBytes)
			if err != nil {
				return syscallSuccess(1) // invalid point
			} else {
				return syscallSuccess(0) // valid point
			}
		}

	case curve25519Ristretto:
		{
			err := execCtx.ComputeMeter.Consume(CUCurve25519RistrettoValidatePointCost)
			if err != nil {
				return syscallCuErr()
			}

			pointBytes, err := vm.Translate(pointAddr, 32, false)
			if err != nil {
				return syscallErr(err)
			}

			var b [32]byte
			copy(b[:], pointBytes)

			var point ristretto.Point
			isValid := point.SetBytes(&b)
			if !isValid {
				return syscallSuccess(1) // invalid point
			} else {
				return syscallSuccess(0) // valid point
			}
		}

	default:
		{
			if execCtx.GlobalCtx.Features.IsActive(features.AbortOnInvalidCurve) {
				return syscallErrCustom("SyscallError::InvalidAttribute")
			} else {
				return syscallSuccess(1)
			}
		}
	}
}

var SyscallValidatePoint = sbpf.SyscallFunc2(SyscallCurveValidatePointImpl)
