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
	Args:  cobra.NoArgs,
	Run:   run,
}

func init() {
}

func run(c *cobra.Command, _ []string) {
	snapshotFileName := "/mnt/solana-snapshots/snapshot-288081692-9xDqLJKJaRgeQwVkyEMEiTV6e4TZbJUoQ25p4QpCweuh.tar.zst"

	err := snapshot.BuildAccountsIndexFromSnapshot(snapshotFileName)
	if err != nil {
		klog.Exitf("failed to populate new accounts db from snapshot %s: %s", snapshotFileName, err)
	}

	klog.Infof("successfully created accounts db from snapshot %s", snapshotFileName)
}
