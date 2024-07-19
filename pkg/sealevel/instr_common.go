package sealevel

import (
	"bytes"
	"crypto/sha256"

	"github.com/gagliardetto/solana-go"
)

func ValidateAndCreateWithSeed(base solana.PublicKey, seed string, owner solana.PublicKey) (solana.PublicKey, error) {
	if len(seed) > solana.MaxSeedLength {
		return solana.PublicKey{}, PubkeyErrMaxSeedLengthExceeded
	}

	slice := owner[(len(owner) - len(solana.PDA_MARKER)):]
	if bytes.Equal(slice, []byte(solana.PDA_MARKER)) {
		return solana.PublicKey{}, PubkeyErrIllegalOwner
	}

	b := make([]byte, 0, 64+len(seed))
	b = append(b, base[:]...)
	b = append(b, seed[:]...)
	b = append(b, owner[:]...)
	hash := sha256.Sum256(b)
	return solana.PublicKeyFromBytes(hash[:]), nil
}
