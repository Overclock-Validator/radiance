package genesis

import (
	"time"

	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/runtime"
)

// Genesis contains the genesis state of a Solana ledger.
type Genesis struct {
	CreationTime  time.Time
	Accounts      []AccountEntry
	Builtins      []BuiltinProgram
	RewardPools   []AccountEntry
	TicksPerSlot  uint64
	PohParams     runtime.PohParams
	Fees          runtime.FeeParams
	Rent          runtime.RentParams
	Inflation     runtime.InflationParams
	EpochSchedule runtime.EpochSchedule
	ClusterID     uint32
}

type AccountEntry struct {
	Pubkey [32]byte
	accounts.Account
}

type BuiltinProgram struct {
	Key    string
	Pubkey [32]byte
}

func (g *Genesis) FillAccounts(state accounts.Accounts) {
	for _, acc := range g.Accounts {
		state.SetAccount(&acc.Pubkey, &acc.Account)
	}
}
