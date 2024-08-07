package sealevel

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"filippo.io/edwards25519"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/keep-network/keep-core/pkg/altbn128"
	r255 "github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/safemath"
	"go.firedancer.io/radiance/pkg/sbpf"
)

// curve types
const (
	Curve25519Edwards   = 0
	Curve25519Ristretto = 1
)

const (
	CurvePointBytesLen  = 32
	CurveScalarBytesLen = 32
)

// curve operations
const (
	CurveOpAdd = 0
	CurveOpSub = 1
	CurveOpMul = 2
)

// alt bn128 compression operations
const (
	AltBn128G1Compress   = 0
	AltBn128G1Decompress = 1
	AltBn128G2Compress   = 2
	AltBn128G2Decompress = 3
)

const (
	Bn128G1Len           = 64
	Bn128G2Len           = 128
	Bn128G1CompressedLen = 32
	Bn128G2CompressedLen = 64
)

// alt bn128 operations
const (
	AltBn128Add     = 0
	AltBn128Sub     = 1
	AltBn128Mul     = 2
	AltBn128Pairing = 3
)

// alt bn128 input/output lengths
const (
	AltBn128AdditionInputLen        = 128
	AltBn128MultiplicationInputLen  = 128
	AltBn128PairingElementLen       = 192
	AltBn128AdditionOutputLen       = 64
	AltBn128MultiplicationOutputLen = 64
	AltBn128PairingOutputLen        = 32
	AltBn128FieldSize               = 32
	AltBn128PointSize               = 64
)

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

func handleEdwardsCurveGroupOps(vm sbpf.VM, groupOp, leftInputAddr, rightInputAddr, resultPointAddr uint64) (uint64, error) {
	execCtx := executionCtx(vm)

	switch groupOp {
	case CurveOpAdd:
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

	case CurveOpSub:
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

	case CurveOpMul:
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
	case CurveOpAdd:
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

	case CurveOpSub:
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

	case CurveOpMul:
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

// gfP2, G2FromInts(), and LeftPadTo32Bytes() are borrowed from https://github.com/keep-network/keep-core
// because their altbn128 package does not export the gfP2 type, which is needed to call G2FromInts()

type gfP2 struct {
	x, y *big.Int
}

func LeftPadTo32Bytes(bytes []byte) ([]byte, error) {
	expectedByteLen := 32
	if len(bytes) > expectedByteLen {
		return nil, fmt.Errorf(
			"cannot pad %v byte array to %v bytes", len(bytes), expectedByteLen,
		)
	}

	result := make([]byte, 0)
	if len(bytes) < expectedByteLen {
		result = make([]byte, expectedByteLen-len(bytes))
	}
	result = append(result, bytes...)

	return result, nil
}

func G2FromInts(x *gfP2, y *gfP2) (*bn256.G2, error) {

	if len(x.x.Bytes()) > 32 || len(x.y.Bytes()) > 32 || len(y.x.Bytes()) > 32 || len(y.y.Bytes()) > 32 {
		return nil, errors.New("points on G2 are limited to two 256-bit coordinates")
	}

	paddedXX, _ := LeftPadTo32Bytes(x.x.Bytes())
	paddedXY, _ := LeftPadTo32Bytes(x.y.Bytes())
	paddedX := append(paddedXY, paddedXX...)

	paddedYX, _ := LeftPadTo32Bytes(y.x.Bytes())
	paddedYY, _ := LeftPadTo32Bytes(y.y.Bytes())
	paddedY := append(paddedYY, paddedYX...)

	m := append(paddedX, paddedY...)

	g2 := new(bn256.G2)

	_, err := g2.Unmarshal(m)

	return g2, err
}

func SyscallAltBn128CompressionImpl(vm sbpf.VM, op, inputAddr, inputLen, resultAddr uint64) (uint64, error) {

	var cost uint64
	var outputLen uint64

	switch op {
	case AltBn128G1Compress:
		{
			cost = CUSyscallBaseCost + CUBn128G1Compress
			outputLen = Bn128G1CompressedLen
		}

	case AltBn128G1Decompress:
		{
			cost = CUSyscallBaseCost + CUBn128G1Decompress
			outputLen = Bn128G1Len
		}

	case AltBn128G2Compress:
		{
			cost = CUSyscallBaseCost + CUBn128G2Compress
			outputLen = Bn128G2CompressedLen
		}

	case AltBn128G2Decompress:
		{
			cost = CUSyscallBaseCost + CUBn128G2Decompress
			outputLen = Bn128G2Len
		}

	default:
		{
			return syscallErrCustom("SyscallError::InvalidAttribute")
		}
	}

	execCtx := executionCtx(vm)
	err := execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return syscallCuErr()
	}

	inputSlice, err := vm.Translate(inputAddr, inputLen, false)
	if err != nil {
		return syscallErr(err)
	}

	callResult, err := vm.Translate(resultAddr, outputLen, true)
	if err != nil {
		return syscallErr(err)
	}

	switch op {
	case AltBn128G1Compress:
		{
			if inputLen != Bn128G1Len {
				return syscallSuccess(1)
			}

			x := new(big.Int).SetBytes(inputSlice[:32])
			y := new(big.Int).SetBytes(inputSlice[32:])

			pointUncompressed, err := altbn128.G1FromInts(x, y)
			if err != nil {
				return syscallSuccess(1)
			}

			pointCompressed := altbn128.G1Point{G1: pointUncompressed}.Compress()
			copy(callResult, pointCompressed)

			return syscallSuccess(0)
		}

	case AltBn128G1Decompress:
		{
			if inputLen != Bn128G1CompressedLen {
				return syscallSuccess(1)
			}

			point, err := altbn128.DecompressToG1(inputSlice)
			if err != nil {
				return syscallSuccess(1)
			}

			pointBytes := point.Marshal()
			copy(callResult, pointBytes)

			return syscallSuccess(0)
		}

	case AltBn128G2Compress:
		{
			if inputLen != Bn128G2Len {
				return syscallSuccess(1)
			}

			x1 := new(big.Int).SetBytes(inputSlice[:32])
			y1 := new(big.Int).SetBytes(inputSlice[32:64])
			x2 := new(big.Int).SetBytes(inputSlice[64:96])
			y2 := new(big.Int).SetBytes(inputSlice[96:128])

			xVal := gfP2{x: x1, y: y1}
			yVal := gfP2{x: x2, y: y2}

			pointUncompressed, err := G2FromInts(&xVal, &yVal)
			if err != nil {
				return syscallSuccess(1)
			}

			pointCompressed := altbn128.G2Point{G2: pointUncompressed}.Compress()
			copy(callResult, pointCompressed)

			return syscallSuccess(0)
		}

	case AltBn128G2Decompress:
		{
			if inputLen != Bn128G2CompressedLen {
				return syscallSuccess(1)
			}

			point, err := altbn128.DecompressToG2(inputSlice)
			if err != nil {
				return syscallSuccess(1)
			}

			pointBytes := point.Marshal()
			copy(callResult, pointBytes)

			return syscallSuccess(0)
		}

	default:
		{
			return syscallErrCustom("SyscallError::InvalidAttribute")
		}
	}
}

var SyscallAltBn128Compression = sbpf.SyscallFunc4(SyscallAltBn128CompressionImpl)

func SyscallAltBn128Impl(vm sbpf.VM, groupOp, inputAddr, inputLen, resultAddr uint64) (uint64, error) {
	var cost uint64
	var outputLen uint64

	switch groupOp {
	case AltBn128Add:
		{
			cost = CUBn128AdditionCost
			outputLen = AltBn128AdditionOutputLen
		}

	case AltBn128Mul:
		{
			cost = CUBn128MultiplicationCost
			outputLen = AltBn128MultiplicationOutputLen
		}

	case AltBn128Pairing:
		{
			elementLen := inputLen / AltBn128PairingElementLen
			cost = safemath.SaturatingAddU64(inputLen, CUBn128PairingOnePairCostFirst+(CUBn128PairingOnePairCostOther*(safemath.SaturatingSubU64(elementLen, 1)))+CUSha256BaseCost+AltBn128PairingOutputLen)
			outputLen = AltBn128PairingOutputLen
		}

	default:
		{
			return syscallErrCustom("SyscallError::InvalidAttribute")
		}
	}

	execCtx := executionCtx(vm)
	err := execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return syscallCuErr()
	}

	inputSlice, err := vm.Translate(inputAddr, inputLen, false)
	if err != nil {
		return syscallErr(err)
	}

	callResult, err := vm.Translate(resultAddr, outputLen, true)
	if err != nil {
		return syscallErr(err)
	}

	switch groupOp {
	case AltBn128Add:
		{
			if inputLen > AltBn128AdditionInputLen {
				return syscallSuccess(1)
			}

			x1 := new(big.Int).SetBytes(inputSlice[:32])
			y1 := new(big.Int).SetBytes(inputSlice[32:64])

			point1, err := altbn128.G1FromInts(x1, y1)
			if err != nil {
				return syscallSuccess(1)
			}

			x2 := new(big.Int).SetBytes(inputSlice[64:96])
			y2 := new(big.Int).SetBytes(inputSlice[96:128])

			point2, err := altbn128.G1FromInts(x2, y2)
			if err != nil {
				return syscallSuccess(1)
			}

			resultPoint := new(bn256.G1).Add(point1, point2)

			resultBytes := resultPoint.Marshal()
			copy(callResult, resultBytes)

			return syscallSuccess(0)
		}

	case AltBn128Mul:
		{
			if inputLen > AltBn128MultiplicationInputLen {
				return syscallSuccess(1)
			}

			x1 := new(big.Int).SetBytes(inputSlice[:32])
			y1 := new(big.Int).SetBytes(inputSlice[32:64])

			point, err := altbn128.G1FromInts(x1, y1)
			if err != nil {
				return syscallSuccess(1)
			}

			scalar := new(big.Int).SetBytes(inputSlice[64:])

			resultPoint := new(bn256.G1).ScalarMult(point, scalar)

			resultBytes := resultPoint.Marshal()
			copy(callResult, resultBytes)

			return syscallSuccess(0)
		}

	case AltBn128Pairing:
		{
			if (inputLen % AltBn128PairingElementLen) != 0 {
				return syscallSuccess(1)
			}

			g1Vals := make([]*bn256.G1, 0)
			g2Vals := make([]*bn256.G2, 0)

			for count := uint64(0); count < (inputLen / AltBn128PairingElementLen); count++ {
				g1x := new(big.Int).SetBytes(inputSlice[:(count * 32)])
				g1y := new(big.Int).SetBytes(inputSlice[count*32 : count*64])
				g1, err := altbn128.G1FromInts(g1x, g1y)
				if err != nil {
					return syscallSuccess(1)
				}
				g1Vals = append(g1Vals, g1)

				x1 := new(big.Int).SetBytes(inputSlice[count*64 : count*96])
				y1 := new(big.Int).SetBytes(inputSlice[count*96 : count*128])
				x2 := new(big.Int).SetBytes(inputSlice[count*128 : count*160])
				y2 := new(big.Int).SetBytes(inputSlice[count*160 : count*192])

				xVal := gfP2{x: x1, y: y1}
				yVal := gfP2{x: x2, y: y2}

				g2, err := G2FromInts(&xVal, &yVal)
				if err != nil {
					return syscallSuccess(1)
				}
				g2Vals = append(g2Vals, g2)
			}

			if bn256.PairingCheck(g1Vals, g2Vals) {
				out := make([]byte, 32)
				out[31] = 1
				copy(callResult, out)
			} else {
				out := make([]byte, 32)
				copy(callResult, out)
			}

			return syscallSuccess(0)
		}

	default:
		{
			return syscallErrCustom("SyscallError::InvalidAttribute")
		}
	}

}

var SyscallAltBn128 = sbpf.SyscallFunc4(SyscallAltBn128CompressionImpl)
