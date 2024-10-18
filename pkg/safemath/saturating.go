// The safemath package implements helper functions for safe handling of integers.
//
// This file implements integer operations that 'saturate' at the upper and lower bounds
// of the relevant type instead of overflowing.

package safemath

import (
	"math"
	"math/bits"

	"github.com/ryanavella/wide"
)

// SaturatingAddU8 adds two uint8's together and saturates at the numerical boundary
// if an overflow would have occurred.
func SaturatingAddU8(a, b uint8) uint8 {
	result := a + b
	if result < a {
		return math.MaxUint8
	}
	return result
}

// SaturatingMulU8 multiplies two uint8's together and saturates at the numerical boundary
// if an overflow would have occurred.
func SaturatingMulU8(a, b uint8) uint8 {
	if a == 0 || b == 0 {
		return 0
	}
	result := a * b
	if result < a {
		return math.MaxUint8
	}
	return result
}

// SaturatingSubU8 computes `a - b` for two uint8's and saturates at the numerical boundary
// if an underflow would have occurred.
func SaturatingSubU8(a, b uint8) uint8 {
	if a < b {
		return 0
	}
	return a - b
}

// SaturatingAddU16 adds two uint16's together and saturates at the numerical boundary
// if an overflow would have occurred.
func SaturatingAddU16(a, b uint16) uint16 {
	result := a + b
	if result < a {
		return math.MaxUint16
	}
	return result
}

// SaturatingMulU16 multiplies two uint16's together and saturates at the numerical boundary
// if an overflow would have occurred.
func SaturatingMulU16(a, b uint16) uint16 {
	if a == 0 || b == 0 {
		return 0
	}
	result := a * b
	if result < a {
		return math.MaxUint16
	}
	return result
}

// SaturatingSubU16 computes `a - b` for two uint16's and saturates at the numerical
// boundary (zero) if an underflow would have occurred.
func SaturatingSubU16(a, b uint16) uint16 {
	if a < b {
		return 0
	}
	return a - b
}

// SaturatingAddU32 adds two uint32's together and saturates at the numerical boundary
// if an overflow would have occurred.
func SaturatingAddU32(a, b uint32) uint32 {
	result, carry := bits.Add32(a, b, 0)
	return result | uint32(-int32(carry))
}

// SaturatingMulU32 multiplies two uint32's together and saturates at the numerical boundary
// if an overflow would have occurred.
func SaturatingMulU32(a, b uint32) uint32 {
	overflow, result := bits.Mul32(a, b)
	if overflow > 0 {
		return math.MaxUint32
	}
	return result
}

// SaturatingSubU32 computes `a - b` for two uint32's and saturates at the numerical
// boundary (zero) if an underflow would have occurred.
func SaturatingSubU32(a, b uint32) uint32 {
	result, borrow := bits.Sub32(a, b, 0)
	if borrow == 1 {
		return 0
	}
	return result
}

// SaturatingAddU64 adds two uint64's together and saturates at the numerical boundary
// if an overflow would have occurred.
func SaturatingAddU64(a, b uint64) uint64 {
	result, carry := bits.Add64(a, b, 0)
	return result | uint64(-int64(carry))
}

func SaturatingAddU128(a, b wide.Uint128) wide.Uint128 {
	result := a.Add(b)
	if result.Cmp(a) == -1 {
		return wide.NewUint128(math.MaxUint64, math.MaxUint64)
	}
	return result
}

// SaturatingMulU64 multiplies two uint64's together and saturates at the numerical boundary
// if an overflow would have occurred.
func SaturatingMulU64(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi > 0 {
		return math.MaxUint64
	}
	return lo
}

// SaturatingSubU64 computes `a - b` for two uint64's and saturates at the numerical
// boundary (zero) if an underflow would have occurred.
func SaturatingSubU64(a, b uint64) uint64 {
	result, borrow := bits.Sub64(a, b, 0)
	if borrow == 1 {
		return 0
	}
	return result
}

func SaturatingPow(n uint64, m uint32) uint64 {
	if m == 0 {
		return 1
	}

	if m == 1 {
		return n
	}

	result := n
	for i := uint32(2); i <= m; i++ {
		x := result * n
		if (x / n) != result {
			return math.MaxUint64
		} else {
			result = x
		}
	}
	return result
}
