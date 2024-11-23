//go:build !lite

package node

import (
	"fmt"

	"github.com/gagliardetto/solana-go/rpc"
	"github.com/spf13/cobra"
	"go.firedancer.io/radiance/pkg/accountsdb"
	"go.firedancer.io/radiance/pkg/replay"
	"go.firedancer.io/radiance/pkg/rpcclient"
	"go.firedancer.io/radiance/pkg/snapshot"
	"k8s.io/klog/v2"
)

var (
	Cmd = cobra.Command{
		Use:   "verifier",
		Short: "Run mithril verifier node",
		Run:   run,
	}

	loadFromSnapshot   bool
	loadFromAccountsDb bool
	updateAccountsDb   bool
	path               string
	outputDir          string
	slot               int64
)

func init() {
	Cmd.Flags().BoolVarP(&loadFromSnapshot, "snapshot", "s", false, "Load from a full snapshot")
	Cmd.Flags().BoolVarP(&loadFromAccountsDb, "accountsdb", "a", false, "Load from AccountsDB")
	Cmd.Flags().BoolVarP(&updateAccountsDb, "update-accounts-db", "u", false, "Update accountsdb after execution")
	Cmd.Flags().StringVarP(&path, "path", "p", "", "Path of full snapshot or AccountsDB to load from")
	Cmd.Flags().StringVarP(&outputDir, "out", "o", "", "Output path for writing AccountsDB data to")
	Cmd.Flags().Int64VarP(&slot, "slot", "b", -1, "Block at which to begin replaying")
}

func newBlockFromBlockResult(blockResult *rpc.GetBlockResult) (*replay.Block, error) {
	block := new(replay.Block)

	for _, tx := range blockResult.Transactions {
		txParsed, err := tx.GetTransaction()
		if err != nil {
			return nil, err
		}
		block.Transactions = append(block.Transactions, txParsed)
		block.TxMetas = append(block.TxMetas, tx.Meta)
	}

	block.Blockhash = blockResult.Blockhash
	block.RecentBlockhash = blockResult.PreviousBlockhash

	for _, tx := range block.Transactions {
		block.NumSignatures += uint64(tx.Message.Header.NumRequiredSignatures)
	}

	return block, nil
}

func run(c *cobra.Command, args []string) {

	if !loadFromSnapshot && !loadFromAccountsDb {
		klog.Errorf("must specify either to load from a snapshot or from an existing AccountsDB")
		return
	}

	if slot < 0 {
		if loadFromAccountsDb {
			klog.Errorf("must specify a slot at which to begin replaying")
			return
		}
	}

	var err error
	var accountsDbDir string

	if loadFromSnapshot {
		if path == "" || outputDir == "" {
			klog.Errorf("must specify snapshot path and directory path for writing generated AccountsDB")
			return
		}

		klog.Infof("building AccountsDB from snapshot at %s\n", path)

		// extract accountvecs from full snapshot, build accountsdb index, and write it all out to disk
		err = snapshot.BuildAccountsIndexFromSnapshot(path, outputDir)
		if err != nil {
			klog.Exitf("failed to populate new accounts db from snapshot %s: %s", path, err)
		}

		klog.Infof("successfully created accounts db from snapshot %s", path)

		// just processing the snapshot - not executing blocks.
		if slot < 0 {
			return
		}

		accountsDbDir = outputDir
	} else if loadFromAccountsDb {
		if path == "" {
			klog.Fatalf("must specify an AccountsDB directory path to load from")
		}

		accountsDbDir = path
	}

	klog.Infof("loading from AccountsDB at %s", accountsDbDir)

	accountsDb, err := accountsdb.OpenDb(accountsDbDir)
	if err != nil {
		klog.Fatalf("unable to open accounts db %s\n", accountsDbDir)
	}
	defer accountsDb.CloseDb()

	manifest, err := snapshot.LoadManifestFromFile(fmt.Sprintf("%s/manifest", accountsDbDir))
	if err != nil {
		klog.Fatalf("unable to open manifest file")
	}

	rpcc := rpcclient.NewRpcClient("https://api.mainnet-beta.solana.com")
	blockResult, err := rpcc.GetBlockFinalized(uint64(slot))
	if err != nil {
		klog.Fatalf("error fetching block: %s\n", err)
	}

	block, err := newBlockFromBlockResult(blockResult)
	if err != nil {
		klog.Fatalf("error creating block from BlockResult: %s\n", err)
	}

	leader, err := rpcc.GetLeaderForSlot(uint64(slot))
	if err != nil {
		klog.Fatalf("error fetching leader for slot: %s\n", err)
	}

	block.Slot = uint64(slot)
	block.ParentBankhash = manifest.Bank.Hash
	block.Manifest = manifest
	block.Leader = leader
	block.Reward = replay.BlockRewardsInfo{Leader: blockResult.Rewards[0].Pubkey, Lamports: uint64(blockResult.Rewards[0].Lamports), PostBalance: blockResult.Rewards[0].PostBalance}

	err = replay.ProcessBlock(accountsDb, block, updateAccountsDb)
	if err != nil {
		klog.Errorf("error encountered during block replay: %s\n", err)
	} else {
		klog.Infof("block replayed successfully.\n")
	}
}
