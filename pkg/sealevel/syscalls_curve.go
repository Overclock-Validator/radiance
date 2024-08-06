package sealevel

import (
	"bytes"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/bwesterb/go-ristretto"
	r255 "github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/safemath"
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

func unmarshalEdwardsScalars(scalarsBytes []byte) ([]*edwards25519.Scalar, error) {
	scalars := make([]*edwards25519.Scalar, 0)
	reader := bytes.NewReader(scalarsBytes)

	for count := 0; count < len(scalarsBytes)/32; count++ {
		scalarBuf := make([]byte, 32)

		n, err := reader.Read(scalarBuf)
		if n != 32 || err != nil {
			return nil, fmt.Errorf("not enough bytes deserializing scalars")
		}

		var scalar edwards25519.Scalar
		_, err = scalar.SetBytesWithClamping(scalarBuf)
		if err != nil {
			return nil, fmt.Errorf("not enough bytes deserializing scalars")
		}

		scalars = append(scalars, &scalar)
	}

	return scalars, nil
}

func unmarshalEdwardsPoints(pointsBytes []byte) ([]*edwards25519.Point, error) {
	points := make([]*edwards25519.Point, 0)
	reader := bytes.NewReader(pointsBytes)

	for count := 0; count < len(pointsBytes)/32; count++ {
		pointBuf := make([]byte, 32)

		n, err := reader.Read(pointBuf)
		if n != 32 || err != nil {
			return nil, fmt.Errorf("not enough bytes deserializing points")
		}

		var point edwards25519.Point
		_, err = point.SetBytes(pointBuf)
		if err != nil {
			return nil, fmt.Errorf("not enough bytes deserializing points")
		}

		points = append(points, &point)
	}

	return points, nil
}

func unmarshalRistrettoScalars(scalarsBytes []byte) ([]*r255.Scalar, error) {
	scalars := make([]*r255.Scalar, 0)
	reader := bytes.NewReader(scalarsBytes)

	for count := 0; count < len(scalarsBytes)/32; count++ {
		scalarBuf := make([]byte, 32)

		n, err := reader.Read(scalarBuf)
		if n != 32 || err != nil {
			return nil, fmt.Errorf("not enough bytes deserializing scalars")
		}

		var scalar r255.Scalar
		_, err = scalar.SetBytesWithClamping(scalarBuf)
		if err != nil {
			return nil, fmt.Errorf("not enough bytes deserializing scalars")
		}

		scalars = append(scalars, &scalar)
	}

	return scalars, nil
}

func unmarshalRistrettoElements(elementsBytes []byte) ([]*r255.Element, error) {
	elements := make([]*r255.Element, 0)
	reader := bytes.NewReader(elementsBytes)

	for count := 0; count < len(elementsBytes)/32; count++ {
		elementBuf := make([]byte, 32)

		n, err := reader.Read(elementBuf)
		if n != 32 || err != nil {
			return nil, fmt.Errorf("not enough bytes deserializing element")
		}

		var element r255.Element
		_, err = element.SetCanonicalBytes(elementBuf)
		if err != nil {
			return nil, fmt.Errorf("error deserializing ristretto element")
		}

		elements = append(elements, &element)
	}

	return elements, nil
}

func SyscallCurveMultiscalarMultiplicationImpl(vm sbpf.VM, curveId, scalarsAddr, pointsAddr, pointsLen, resultPointAddr uint64) (uint64, error) {
	execCtx := executionCtx(vm)

	if pointsLen > 512 {
		return syscallErrCustom("SyscallError::InvalidLength")
	}

	switch curveId {
	case curve25519Edwards:
		{
			cost := CUCurve25519EdwardsMsmBaseCost + (CUCurve25519EdwardsMsmIncrementalCost * (safemath.SaturatingSubU64(pointsLen, 1)))
			err := execCtx.ComputeMeter.Consume(cost)
			if err != nil {
				return syscallCuErr()
			}

			scalarsBytes, err := vm.Translate(scalarsAddr, pointsLen*32, false)
			if err != nil {
				return syscallErr(err)
			}

			scalars, err := unmarshalEdwardsScalars(scalarsBytes)
			if err != nil {
				return syscallErr(err)
			}

			pointsBytes, err := vm.Translate(scalarsAddr, pointsLen*32, false)
			if err != nil {
				return syscallErr(err)
			}

			points, err := unmarshalEdwardsPoints(pointsBytes)
			if err != nil {
				return syscallErr(err)
			}

			resultPoint := new(edwards25519.Point).MultiScalarMult(scalars, points)

			resultSlice, err := vm.Translate(resultPointAddr, 32, true)
			if err != nil {
				return syscallErr(err)
			}
			copy(resultSlice, resultPoint.Bytes())
			return syscallSuccess(0)
		}

	case curve25519Ristretto:
		{
			cost := CUCurve25519RistrettoMsmBaseCost + (CUCurve25519RistrettoMsmIncrementalCost * (safemath.SaturatingSubU64(pointsLen, 1)))
			err := execCtx.ComputeMeter.Consume(cost)
			if err != nil {
				return syscallCuErr()
			}

			scalarsBytes, err := vm.Translate(scalarsAddr, pointsLen*32, false)
			if err != nil {
				return syscallErr(err)
			}

			scalars, err := unmarshalRistrettoScalars(scalarsBytes)
			if err != nil {
				return syscallErr(err)
			}

			pointsBytes, err := vm.Translate(scalarsAddr, pointsLen*32, false)
			if err != nil {
				return syscallErr(err)
			}

			points, err := unmarshalRistrettoElements(pointsBytes)
			if err != nil {
				return syscallErr(err)
			}

			resultPoint := new(r255.Element).MultiScalarMult(scalars, points)

			resultSlice, err := vm.Translate(resultPointAddr, 32, true)
			if err != nil {
				return syscallErr(err)
			}
			copy(resultSlice, resultPoint.Bytes())
			return syscallSuccess(0)
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

var SyscallCurveMultiscalarMultiplication = sbpf.SyscallFunc5(SyscallCurveMultiscalarMultiplicationImpl)
