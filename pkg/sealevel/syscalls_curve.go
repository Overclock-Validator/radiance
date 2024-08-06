package sealevel

import (
	"bytes"
	"fmt"

	"filippo.io/edwards25519"
	r255 "github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/safemath"
	"go.firedancer.io/radiance/pkg/sbpf"
)

const Curve25519Edwards = 0
const Curve25519Ristretto = 1

const CurvePointBytesLen = 32
const CurveScalarBytesLen = 32

func SyscallCurveValidatePointImpl(vm sbpf.VM, curveId, pointAddr uint64) (uint64, error) {
	execCtx := executionCtx(vm)

	switch curveId {
	case Curve25519Edwards:
		{
			err := execCtx.ComputeMeter.Consume(CUCurve25519EdwardsValidatePointCost)
			if err != nil {
				return syscallCuErr()
			}

			pointBytes, err := vm.Translate(pointAddr, CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}

			var point edwards25519.Point
			_, err = point.SetBytes(pointBytes)
			if err != nil {
				return syscallSuccess(1)
			} else {
				return syscallSuccess(0)
			}
		}

	case Curve25519Ristretto:
		{
			err := execCtx.ComputeMeter.Consume(CUCurve25519RistrettoValidatePointCost)
			if err != nil {
				return syscallCuErr()
			}

			pointBytes, err := vm.Translate(pointAddr, CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}

			_, err = new(r255.Element).SetCanonicalBytes(pointBytes)
			if err != nil {
				return syscallSuccess(1)
			} else {
				return syscallSuccess(0)
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

	for count := 0; count < len(scalarsBytes)/CurveScalarBytesLen; count++ {
		scalarBuf := make([]byte, CurveScalarBytesLen)

		n, err := reader.Read(scalarBuf)
		if n != CurveScalarBytesLen || err != nil {
			return nil, fmt.Errorf("not enough bytes deserializing scalars")
		}

		var scalar edwards25519.Scalar
		_, err = scalar.SetCanonicalBytes(scalarBuf)
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

	for count := 0; count < len(pointsBytes)/CurvePointBytesLen; count++ {
		pointBuf := make([]byte, CurvePointBytesLen)

		n, err := reader.Read(pointBuf)
		if n != CurvePointBytesLen || err != nil {
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

	for count := 0; count < len(scalarsBytes)/CurveScalarBytesLen; count++ {
		scalarBuf := make([]byte, CurveScalarBytesLen)

		n, err := reader.Read(scalarBuf)
		if n != CurveScalarBytesLen || err != nil {
			return nil, fmt.Errorf("not enough bytes deserializing scalars")
		}

		var scalar r255.Scalar
		_, err = scalar.SetCanonicalBytes(scalarBuf)
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

	for count := 0; count < len(elementsBytes)/CurvePointBytesLen; count++ {
		elementBuf := make([]byte, CurvePointBytesLen)

		n, err := reader.Read(elementBuf)
		if n != CurvePointBytesLen || err != nil {
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
	case Curve25519Edwards:
		{
			cost := CUCurve25519EdwardsMsmBaseCost + (CUCurve25519EdwardsMsmIncrementalCost * (safemath.SaturatingSubU64(pointsLen, 1)))
			err := execCtx.ComputeMeter.Consume(cost)
			if err != nil {
				return syscallCuErr()
			}

			scalarsBytes, err := vm.Translate(scalarsAddr, pointsLen*CurveScalarBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}

			scalars, err := unmarshalEdwardsScalars(scalarsBytes)
			if err != nil {
				return syscallErr(err)
			}

			pointsBytes, err := vm.Translate(scalarsAddr, pointsLen*CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}

			points, err := unmarshalEdwardsPoints(pointsBytes)
			if err != nil {
				return syscallErr(err)
			}

			resultPoint := new(edwards25519.Point).MultiScalarMult(scalars, points)

			resultSlice, err := vm.Translate(resultPointAddr, CurvePointBytesLen, true)
			if err != nil {
				return syscallErr(err)
			}
			copy(resultSlice, resultPoint.Bytes())
			return syscallSuccess(0)
		}

	case Curve25519Ristretto:
		{
			cost := CUCurve25519RistrettoMsmBaseCost + (CUCurve25519RistrettoMsmIncrementalCost * (safemath.SaturatingSubU64(pointsLen, 1)))
			err := execCtx.ComputeMeter.Consume(cost)
			if err != nil {
				return syscallCuErr()
			}

			scalarsBytes, err := vm.Translate(scalarsAddr, pointsLen*CurveScalarBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}

			scalars, err := unmarshalRistrettoScalars(scalarsBytes)
			if err != nil {
				return syscallErr(err)
			}

			pointsBytes, err := vm.Translate(scalarsAddr, pointsLen*CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}

			points, err := unmarshalRistrettoElements(pointsBytes)
			if err != nil {
				return syscallErr(err)
			}

			resultPoint := new(r255.Element).MultiScalarMult(scalars, points)

			resultSlice, err := vm.Translate(resultPointAddr, CurvePointBytesLen, true)
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

const (
	curveOpAdd = 0
	curveOpSub = 1
	curveOpMul = 2
)

func handleEdwardsCurveGroupOps(vm sbpf.VM, groupOp, leftInputAddr, rightInputAddr, resultPointAddr uint64) (uint64, error) {
	execCtx := executionCtx(vm)

	switch groupOp {
	case curveOpAdd:
		{
			err := execCtx.ComputeMeter.Consume(CUCurve25519EdwardsAddCost)
			if err != nil {
				return syscallCuErr()
			}

			leftPointBytes, err := vm.Translate(leftInputAddr, CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}

			rightPointBytes, err := vm.Translate(rightInputAddr, CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}

			leftPoint, err := new(edwards25519.Point).SetBytes(leftPointBytes)
			if err != nil {
				return syscallErr(err)
			}

			rightPoint, err := new(edwards25519.Point).SetBytes(rightPointBytes)
			if err != nil {
				return syscallErr(err)
			}

			resultPoint := new(edwards25519.Point).Add(leftPoint, rightPoint)

			resultPointSlice, err := vm.Translate(resultPointAddr, CurvePointBytesLen, true)
			if err != nil {
				return syscallErr(err)
			}

			copy(resultPointSlice, resultPoint.Bytes())
			return syscallSuccess(0)
		}

	case curveOpSub:
		{
			err := execCtx.ComputeMeter.Consume(CUCurve25519EdwardsSubCost)
			if err != nil {
				return syscallErr(err)
			}

			leftPointBytes, err := vm.Translate(leftInputAddr, CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}
			leftPoint, err := new(edwards25519.Point).SetBytes(leftPointBytes)
			if err != nil {
				return syscallErr(err)
			}

			rightPointBytes, err := vm.Translate(rightInputAddr, CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}
			rightPoint, err := new(edwards25519.Point).SetBytes(rightPointBytes)
			if err != nil {
				return syscallErr(err)
			}

			resultPoint := new(edwards25519.Point).Subtract(leftPoint, rightPoint)

			resultPointSlice, err := vm.Translate(resultPointAddr, CurvePointBytesLen, true)
			if err != nil {
				return syscallErr(err)
			}

			copy(resultPointSlice, resultPoint.Bytes())
			return syscallSuccess(0)
		}

	case curveOpMul:
		{
			err := execCtx.ComputeMeter.Consume(CUCurve25519EdwardsMulCost)
			if err != nil {
				return syscallErr(err)
			}

			scalarBytes, err := vm.Translate(leftInputAddr, CurveScalarBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}

			inputPointBytes, err := vm.Translate(rightInputAddr, CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}

			scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(scalarBytes)
			if err != nil {
				return syscallErr(err)
			}

			inputPoint, err := new(edwards25519.Point).SetBytes(inputPointBytes)
			if err != nil {
				return syscallErr(err)
			}

			resultPoint := new(edwards25519.Point).ScalarMult(scalar, inputPoint)

			resultPointSlice, err := vm.Translate(resultPointAddr, CurvePointBytesLen, true)
			if err != nil {
				return syscallErr(err)
			}

			copy(resultPointSlice, resultPoint.Bytes())
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

func handleRistrettoCurveGroupOps(vm sbpf.VM, groupOp, leftInputAddr, rightInputAddr, resultPointAddr uint64) (uint64, error) {
	execCtx := executionCtx(vm)

	switch groupOp {
	case curveOpAdd:
		{
			err := execCtx.ComputeMeter.Consume(CUCurve25519RistrettoAddCost)
			if err != nil {
				return syscallCuErr()
			}

			leftPointBytes, err := vm.Translate(leftInputAddr, CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}
			leftPoint, err := new(r255.Element).SetCanonicalBytes(leftPointBytes)

			rightPointBytes, err := vm.Translate(rightInputAddr, CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}
			rightPoint, err := new(r255.Element).SetCanonicalBytes(rightPointBytes)

			resultPoint := new(r255.Element).Add(leftPoint, rightPoint)

			resultPointSlice, err := vm.Translate(resultPointAddr, CurvePointBytesLen, true)
			if err != nil {
				return syscallErr(err)
			}

			copy(resultPointSlice, resultPoint.Bytes())
			return syscallSuccess(0)
		}

	case curveOpSub:
		{
			err := execCtx.ComputeMeter.Consume(CUCurve25519RistrettoSubCost)
			if err != nil {
				return syscallCuErr()
			}

			leftPointBytes, err := vm.Translate(leftInputAddr, CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}
			leftPoint, err := new(r255.Element).SetCanonicalBytes(leftPointBytes)

			rightPointBytes, err := vm.Translate(rightInputAddr, CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}
			rightPoint, err := new(r255.Element).SetCanonicalBytes(rightPointBytes)

			resultPoint := new(r255.Element).Subtract(leftPoint, rightPoint)

			resultPointSlice, err := vm.Translate(resultPointAddr, CurvePointBytesLen, true)
			if err != nil {
				return syscallErr(err)
			}

			copy(resultPointSlice, resultPoint.Bytes())
			return syscallSuccess(0)
		}

	case curveOpMul:
		{
			err := execCtx.ComputeMeter.Consume(CUCurve25519RistrettoAddCost)
			if err != nil {
				return syscallCuErr()
			}

			scalarBytes, err := vm.Translate(leftInputAddr, CurveScalarBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}

			inputPointBytes, err := vm.Translate(rightInputAddr, CurvePointBytesLen, false)
			if err != nil {
				return syscallErr(err)
			}

			scalar, err := new(r255.Scalar).SetCanonicalBytes(scalarBytes)
			if err != nil {
				return syscallErr(err)
			}

			element, err := new(r255.Element).SetCanonicalBytes(inputPointBytes)
			if err != nil {
				return syscallErr(err)
			}

			var resultPoint r255.Element
			resultPoint.ScalarMult(scalar, element)

			resultPointSlice, err := vm.Translate(resultPointAddr, CurvePointBytesLen, true)
			if err != nil {
				return syscallErr(err)
			}

			copy(resultPointSlice, resultPoint.Bytes())
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

func SyscallCurveGroupOpsImpl(vm sbpf.VM, curveId, groupOp, leftInputAddr, rightInputAddr, resultPointAddr uint64) (uint64, error) {
	switch curveId {
	case Curve25519Edwards:
		{
			return handleEdwardsCurveGroupOps(vm, groupOp, leftInputAddr, rightInputAddr, resultPointAddr)
		}

	case Curve25519Ristretto:
		{
			return handleRistrettoCurveGroupOps(vm, groupOp, leftInputAddr, rightInputAddr, resultPointAddr)
		}

	default:
		{
			execCtx := executionCtx(vm)
			if execCtx.GlobalCtx.Features.IsActive(features.AbortOnInvalidCurve) {
				return syscallErrCustom("SyscallError::InvalidAttribute")
			} else {
				return syscallSuccess(1)
			}
		}
	}
}

var SyscallCurveGroupOps = sbpf.SyscallFunc5(SyscallCurveGroupOpsImpl)
