package accounts

import (
	"fmt"

	"go.firedancer.io/radiance/pkg/base58"
)

type MemAccounts struct {
	Map map[[32]byte]*Account
}

func NewMemAccounts() MemAccounts {
	return MemAccounts{
		Map: make(map[[32]byte]*Account),
	}
}

func (m MemAccounts) GetAccount(pubkey *[32]byte) (*Account, error) {
	acct, ok := m.Map[*pubkey]
	if !ok {
		return nil, fmt.Errorf("no such account %s found", base58.Encode(pubkey[:]))
	}
	return acct, nil
}

func (m MemAccounts) SetAccount(pubkey *[32]byte, acct *Account) error {
	m.Map[*pubkey] = acct
	return nil
}
