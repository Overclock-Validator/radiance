package solana

import (
	"crypto/sha256"
	"errors"

	"filippo.io/edwards25519"
)

const MaxSeeds = 16
const MaxSeedLen = 32
const PublicKeyLength = 32
const PdaMarker = "ProgramDerivedAddress"

var (
	ErrSeedLength          = errors.New("Max seeds (16) exceeded")
	ErrAddressLength       = errors.New("Wrong key length; addresses are 32 bytes long")
	ErrOnCurveInvalidSeeds = errors.New("Invalid seeds - generated address must be off-curve")
)

func CreateProgramAddressBytes(seeds [][]byte, programID []byte) ([]byte, error) {
	if len(seeds) > MaxSeeds {
		return nil, ErrSeedLength
	}

	if len(programID) != PublicKeyLength {
		return nil, ErrAddressLength
	}

	hasher := sha256.New()
	for _, seed := range seeds {
		if len(seed) > MaxSeedLen {
			return nil, ErrSeedLength
		}
		hasher.Write(seed)
	}

	hasher.Write(programID)
	hasher.Write([]byte(PdaMarker))
	hash := hasher.Sum(nil)

	if IsOnCurve(hash[:]) {
		return nil, ErrOnCurveInvalidSeeds
	}

	return hash[:], nil
}

// IsOnCurve checks if 'b' is on the ed25519 curve
func IsOnCurve(b []byte) bool {
	_, err := new(edwards25519.Point).SetBytes(b)
	onCurve := err == nil
	return onCurve
}
