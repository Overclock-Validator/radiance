package snapshot

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.firedancer.io/radiance/pkg/accounts"
)

func Test_Snapshot_Load(t *testing.T) {
	manifest, err := UnmarshalManifestFromSnapshot("/Users/shauncolley/snapshot.tar.bz2")
	//manifest, err := LoadManifestFromSnapshot("/path/to/a/snapshot.tar.bz2")
	assert.NoError(t, err)

	fmt.Printf("bank slot: %d, tx count: %d\n", manifest.Bank.Slot, manifest.Bank.TransactionCount)
	fmt.Printf("AppendVec storages: %+v\n", manifest.AccountsDb.Storages)
}

func Test_AppendVec_Filenames(t *testing.T) {
	accountsDb, err := accounts.CreateNewAccountsDb("/Users/shauncolley/accounts.db")
	assert.NoError(t, err)

	err = LoadAccountsToAccountsDbFromSnapshot("/Users/shauncolley/snapshot.tar.bz2", *accountsDb)
	assert.NoError(t, err)
}
