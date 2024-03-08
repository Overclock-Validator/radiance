package accounts

type MemAccounts struct {
	Map map[[32]byte]*Account
}

func NewMemAccounts() MemAccounts {
	return MemAccounts{
		Map: make(map[[32]byte]*Account),
	}
}

func (m MemAccounts) GetAccount(pubkey *[32]byte) (*Account, error) {
	return m.Map[*pubkey], nil
}

func (m MemAccounts) SetAccount(pubkey *[32]byte, acc *Account) error {
	m.Map[*pubkey] = acc
	return nil
}
