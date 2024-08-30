package snapshot

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Snapshot_Load(t *testing.T) {
	manifest, err := UnmarshalManifestFromSnapshot("/Users/shauncolley/snapshot.tar.bz2")
	//manifest, err := LoadManifestFromSnapshot("/path/to/a/snapshot.tar.bz2")
	assert.NoError(t, err)

	fmt.Printf("bank slot: %d, tx count: %d\n", manifest.Bank.Slot, manifest.Bank.TransactionCount)
	fmt.Printf("AppendVec storages: %+v\n", manifest.AccountsDb.Storages)
}

func Test_AppendVec_Filenames(t *testing.T) {
	err := LoadAccountsFromSnapshot("/Users/shauncolley/snapshot.tar.bz2")
	assert.NoError(t, err)
}
