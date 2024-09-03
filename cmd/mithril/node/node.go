//go:build !lite

package node

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/snapshot"
	"k8s.io/klog/v2"
)

var Cmd = cobra.Command{
	Use:   "verifier",
	Short: "Run Solana verifier node",
	Args:  cobra.NoArgs,
	Run:   run,
}

func init() {
}

func run(c *cobra.Command, _ []string) {
	snapshotFileName := "/Users/shauncolley/snapshot.tar.bz2"
	accountsDbFileName := fmt.Sprintf("/tmp/accounts_db_%s", time.Now())

	accountsDb, err := accounts.CreateNewAccountsDb(accountsDbFileName)
	if err != nil {
		klog.Exitf("failed to create new accounts db %s from snapshot %s: %s", accountsDbFileName, snapshotFileName, err)
	}

	err = snapshot.LoadAccountsToAccountsDbFromSnapshot(snapshotFileName, *accountsDb)
	if err != nil {
		klog.Exitf("failed to populate new accounts db from snapshot %s: %s", snapshotFileName, err)
	}

	klog.Infof("successfully created accounts db from snapshot %s", snapshotFileName)
}
