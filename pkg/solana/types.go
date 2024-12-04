package solana

import "github.com/Overclock-Validator/mithril/pkg/base58"

type Hash [32]byte
type Address [32]byte
type Signature [64]byte

func MustAddress(s string) Address {
	var a Address
	if err := a.UnmarshalText([]byte(s)); err != nil {
		panic(err)
	}
	return a
}

func (p *Hash) String() string {
	return base58.Encode(p[:])
}

func (p *Hash) UnmarshalText(b []byte) error {
	if !base58.Decode32((*[32]byte)(p), b) {
		return base58.ErrEncode
	}
	return nil
}

func (p *Address) String() string {
	return (*Hash)(p).String()
}

func (p *Address) UnmarshalText(b []byte) error {
	return (*Hash)(p).UnmarshalText(b)
}
