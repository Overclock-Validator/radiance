//go:build !lite

package node

import (
	"github.com/spf13/cobra"
	"go.firedancer.io/radiance/pkg/snapshot"
	"k8s.io/klog/v2"
)

var Cmd = cobra.Command{
	Use:   "verifier",
	Short: "Run Solana verifier node",
	Args:  cobra.ExactArgs(2),
	Run:   run,
}

func init() {
}

func run(c *cobra.Command, args []string) {
	snapshotFileName := args[0]
	accountsDbDir := args[1]

	err := snapshot.BuildAccountsIndexFromSnapshot(snapshotFileName, accountsDbDir)
	if err != nil {
		klog.Exitf("failed to populate new accounts db from snapshot %s: %s", snapshotFileName, err)
	}

	klog.Infof("successfully created accounts db from snapshot %s", snapshotFileName)
}
