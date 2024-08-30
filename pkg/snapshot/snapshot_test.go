package snapshot

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Snapshot_Load(t *testing.T) {
	//manifest, err := LoadManifestFromSnapshot("/Users/shauncolley/snapshot.tar.bz2")
	manifest, err := LoadManifestFromSnapshot("/path/to/a/snapshot.tar.bz2")
	assert.NoError(t, err)

	fmt.Printf("bank slot: %d, tx count: %d\n", manifest.Bank.Slot, manifest.Bank.TransactionCount)
	fmt.Printf("AppendVec storages: %+v\n", manifest.AccountsDb.Storages)
}
