// The safemath package implements helper functions for safe integer arithmetic.
//
// This file implements 'checked' integer arithmetic for guarding against integer
// overflows and division-by-zero errors.

package safemath

import (
	"errors"
	"math/bits"

	"github.com/ryanavella/wide"
)

var (
	ErrOverflowAdd = errors.New("integer overflow in addition")
	ErrOverflowMul = errors.New("integer overflow in multiplication")
	ErrOverflowSub = errors.New("integer overflow in subtraction")
	ErrDivByZero   = errors.New("divide by zero")
)

// CheckedAddU8 adds two uint8's together, returning an error
// in the event of an overflow.
func CheckedAddU8(a, b uint8) (uint8, error) {
	result := a + b
	if result < a {
		return 0, ErrOverflowAdd
	}
	return result, nil
}

// CheckedMulU8 multiplies two uint8's together, returning an error
// in the event of an overflow.
func CheckedMulU8(a, b uint8) (uint8, error) {
	result := a * b
	if result < a {
		return 0, ErrOverflowMul
	}
	return result, nil
}

// CheckedSubU8 computes `a - b` for two uint8's returning an error in the event
// that a is smaller than b
func CheckedSubU8(a, b uint8) (uint8, error) {
	if a < b {
		return 0, ErrOverflowSub
	}
	return a - b, nil
}

// CheckedDivU8 computes `a / b` for two uint8's, returning an error in the event
// that b is 0
func CheckedDivU8(a, b uint8) (uint8, error) {
	if b == 0 {
		return 0, ErrDivByZero
	}
	return a / b, nil
}

// CheckedAddU16 adds two uint16's together, returning an error in the event
// of an overflow.
func CheckedAddU16(a, b uint16) (uint16, error) {
	result := a + b
	if result < a {
		return 0, ErrOverflowAdd
	}
	return result, nil
}

// CheckedMulU16 multiplies two uint16's together, returning an error in the event
// of an overflow.
func CheckedMulU16(a, b uint16) (uint16, error) {
	result := a * b
	if result < a {
		return 0, ErrOverflowMul
	}
	return result, nil
}

// CheckedSubU16 computes `a - b` for two uint16's, returning an error in the event
// that a is smaller than b
func CheckedSubU16(a, b uint16) (uint16, error) {
	if a < b {
		return 0, ErrOverflowSub
	}
	return a - b, nil
}

// CheckedDivU16 computes `a / b` for two uint16's, returning an error in the event
// that b is 0
func CheckedDivU16(a, b uint16) (uint16, error) {
	if b == 0 {
		return 0, ErrDivByZero
	}
	return a / b, nil
}

// CheckedAddU32 adds two uint32's together, returning an error in the event of an overflow.
func CheckedAddU32(a, b uint32) (uint32, error) {
	sum, carryOut := bits.Add32(a, b, 0)
	if carryOut == 1 {
		return 0, ErrOverflowAdd
	}
	return sum, nil
}

// CheckedMulU32 multiplies two uint32's together, returning an error in the event
// of an overflow.
func CheckedMulU32(a, b uint32) (uint32, error) {
	hi, lo := bits.Mul32(a, b)
	if hi > 0 {
		return 0, ErrOverflowMul
	}
	return lo, nil
}

// CheckedSubU32 computes `a - b` for two uint32's, returning an error in the event that
// a is smaller than b
func CheckedSubU32(a, b uint32) (uint32, error) {
	result, borrow := bits.Sub32(a, b, 0)
	if borrow == 1 {
		return 0, ErrOverflowSub
	}
	return result, nil
}

// CheckedDivU32 computes `a / b` for two uint32's, returning an error in the event
// that b is 0
func CheckedDivU32(a, b uint32) (uint32, error) {
	if b == 0 {
		return 0, ErrDivByZero
	}
	result, _ := bits.Div32(0, a, b)
	return result, nil
}

// CheckedAddU64 adds two uint64's together, returning an error in the event of an overflow.
func CheckedAddU64(a, b uint64) (uint64, error) {
	sum, carryOut := bits.Add64(a, b, 0)
	if carryOut == 1 {
		return 0, ErrOverflowAdd
	}
	return sum, nil
}

// CheckedMulU64 multiplies two uint64's together, returning an error in the event
// of an overflow.
func CheckedMulU64(a, b uint64) (uint64, error) {
	hi, lo := bits.Mul64(a, b)
	if hi > 0 {
		return 0, ErrOverflowMul
	}
	return lo, nil
}

// CheckedSubU64 computes `a - b` for two uint64's, returning an error in the event
// that a is smaller than b
func CheckedSubU64(a, b uint64) (uint64, error) {
	result, borrow := bits.Sub64(a, b, 0)
	if borrow == 1 {
		return 0, ErrOverflowSub
	}
	return result, nil
}

// CheckedDivU64 computes `a / b` for two uint64's, returning an error in the event
// that b is 0
func CheckedDivU64(a, b uint64) (uint64, error) {
	if b == 0 {
		return 0, ErrDivByZero
	}
	result, _ := bits.Div64(0, a, b)
	return result, nil
}

// CheckedAddU128 adds two uint128's together, returning an error in the event of an overflow.
func CheckedAddU128(a, b wide.Uint128) (wide.Uint128, error) {
	result := a.Add(b)
	if result.Cmp(a) == -1 {
		return wide.NewUint128(0, 0), ErrOverflowAdd
	}
	return result, nil
}
