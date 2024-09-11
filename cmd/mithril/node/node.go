//go:build !lite

package node

import (
	"github.com/gagliardetto/solana-go"
	"github.com/spf13/cobra"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/accountsdb"
	"go.firedancer.io/radiance/pkg/sealevel"
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
	path               string
	outputDir          string
)

func init() {
	Cmd.Flags().BoolVarP(&loadFromSnapshot, "snapshot", "s", false, "Load from a full snapshot")
	Cmd.Flags().BoolVarP(&loadFromAccountsDb, "accountsdb", "a", false, "Load from AccountsDB")
	Cmd.Flags().StringVarP(&path, "path", "p", "", "Path of full snapshot or AccountsDB to load from")
	Cmd.Flags().StringVarP(&outputDir, "out", "o", "", "Output path for writing AccountsDB data to")
}

func run(c *cobra.Command, args []string) {

	if !loadFromSnapshot && !loadFromAccountsDb {
		klog.Errorf("must specify either to load from a snapshot or from an existing AccountsDB")
		return
	}

	var accountsDbDir string

	if loadFromSnapshot {
		if path == "" || outputDir == "" {
			klog.Errorf("must specify snapshot path and directory path for writing generated AccountsDB")
			return
		}

		klog.Infof("building AccountsDB from snapshot at %s\n", path)

		// extract accountvecs from full snapshot, build accountsdb index, and write it all out to disk
		err := snapshot.BuildAccountsIndexFromSnapshot(path, outputDir)
		if err != nil {
			klog.Exitf("failed to populate new accounts db from snapshot %s: %s", path, err)
		}

		klog.Infof("successfully created accounts db from snapshot %s", path)

		accountsDbDir = outputDir
	} else if loadFromAccountsDb {
		if path == "" {
			klog.Errorf("must specify an AccountsDB directory path to load from")
			return
		}

		accountsDbDir = path
	}

	klog.Infof("loading from AccountsDB at %s", accountsDbDir)

	accountsDb, err := accountsdb.OpenDb(accountsDbDir)
	if err != nil {
		klog.Fatalf("unable to open accounts db %s\n", accountsDbDir)
	}
	defer accountsDb.CloseDb()

	// token program account
	pubkey1 := solana.MustPublicKeyFromBase58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
	acct1, err := accountsDb.GetAccount(pubkey1)
	if err != nil {
		klog.Fatalf("unable to fetch account %s from accountsdb\n", pubkey1)
	}

	klog.Infof("%+v, owner: %s\n", acct1, solana.PublicKeyFromBytes(acct1.Owner[:]))

	// Overclock validator vote account
	pubkey2 := solana.MustPublicKeyFromBase58("AS3nKBQfKs8fJ8ncyHrdvo4FDT6S8HMRhD75JjCcyr1t")
	acct2, err := accountsDb.GetAccount(pubkey2)
	if err != nil {
		klog.Fatalf("unable to fetch account %s from accountsdb\n", pubkey2)
	}

	klog.Infof("%+v, owner: %s\n", acct2, solana.PublicKeyFromBytes(acct2.Owner[:]))

	dataBytes := make([]byte, 3)
	dataBytes[0] = 'a'
	dataBytes[1] = 'b'
	dataBytes[2] = 'c'
	acct1.Lamports = 13370
	acct1.Owner = sealevel.AddressLookupTableAddr
	acct1.Data = dataBytes

	acct2.Lamports = 13380
	acct2.Owner = sealevel.BpfLoaderUpgradeableAddr
	acct2.Data = dataBytes

	err = accountsDb.StoreAccounts([]*accounts.Account{acct1, acct2}, 13370)
	if err != nil {
		klog.Fatalf("unable to set account to accountsdb\n")
	}

	acct1, err = accountsDb.GetAccount(pubkey1)
	if err != nil {
		klog.Fatalf("unable to fetch account %s from accountsdb\n", pubkey1)
	}

	klog.Infof("%+v, owner: %s\n", acct1, solana.PublicKeyFromBytes(acct1.Owner[:]))

	acct2, err = accountsDb.GetAccount(pubkey2)
	if err != nil {
		klog.Fatalf("unable to fetch account %s from accountsdb\n", pubkey2)
	}

	klog.Infof("%+v, owner: %s\n", acct2, solana.PublicKeyFromBytes(acct2.Owner[:]))
}
