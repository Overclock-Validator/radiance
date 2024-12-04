//go:build !lite

package replay

import (
	"bytes"
	"encoding/hex"

	"github.com/Overclock-Validator/mithril/pkg/accounts"
	"github.com/Overclock-Validator/mithril/pkg/blockstore"
	"github.com/Overclock-Validator/mithril/pkg/genesis"
	"github.com/Overclock-Validator/mithril/pkg/merkletree"
	"github.com/Overclock-Validator/mithril/pkg/poh"
	"github.com/gagliardetto/solana-go"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

var Cmd = cobra.Command{
	Use:   "replay",
	Short: "Replay historical blockchain data",
	Args:  cobra.NoArgs,
	Run:   run,
}

var flags = Cmd.Flags()

var (
	flagGenesis string
	flagDB      string
)

func init() {
	flags.StringVar(&flagGenesis, "genesis", "", "Path to genesis")
	flags.StringVar(&flagDB, "db", "", "Path to RocksDB")
}

func run(c *cobra.Command, _ []string) {
	if flagGenesis == "" {
		klog.Exit("No genesis given")
	}
	if flagDB == "" {
		klog.Exit("No database given")
	}

	// Read genesis, containing the initial set of accounts.
	genesisConfig, genesisHash, err := genesis.ReadGenesisFromFile(flagGenesis)
	if err != nil {
		klog.Exitf("Failed to read genesis: %s", err)
	}
	klog.V(2).Infof("Genesis hash: %s", hex.EncodeToString(genesisHash[:]))

	// Load initial accounts into memory.
	// Obviously, an in-memory database won't cut it for later stages of replay.
	accounts := accounts.NewMemAccounts()
	genesisConfig.FillAccounts(accounts)

	// Open blockstore database.
	db, err := blockstore.OpenReadOnly(flagDB)
	if err != nil {
		klog.Exitf("Failed to open blockstore: %s", err)
	}

	// Open block iterator.
	walker, err := blockstore.NewBlockWalk([]blockstore.WalkHandle{{DB: db}}, 2)
	if err != nil {
		klog.Fatal(err)
	}
	defer walker.Close()

	// PoH delay function (SHA-256 hash chain).
	var chain poh.State
	chain = *genesisHash

replay:
	for slot := uint64(0); true; slot++ {
		klog.V(2).Infof("Slot %d: %x", slot, chain)
		meta, ok := walker.Next()
		if !ok {
			break
		}
		entries, err := walker.Entries(meta)
		if err != nil {
			klog.Errorf("Failed to get entries of block %d: %s", slot, err)
			break
		}
		cum := uint64(0) // Cumulative hash count between mixins
		for i, batch := range entries {
			for j, entry := range batch {
				cum += entry.NumHashes
				klog.V(7).Infof("Replay slot=%d entry=%02d/%02d hash=%s hash_cnt=%d cum=%d txs=%d",
					slot, i, j, hex.EncodeToString(entry.Hash[:]), entry.NumHashes, cum, len(entry.Txns))
				if len(entry.Txns) != 0 {
					numHashes := entry.NumHashes
					if numHashes > 1 {
						chain.Hash(uint(entry.NumHashes - 1))
					}

					var txSigs [][]byte
					for _, tx := range entry.Txns {
						if len(tx.Signatures) == 0 {
							klog.Errorf("Invalid tx: Zero signatures")
							break replay
						}
						for i := range tx.Signatures {
							txSigs = append(txSigs, tx.Signatures[i][:])
						}
					}

					sigTree := merkletree.HashNodes(txSigs)
					klog.V(7).Infof("Mixin: %x", sigTree.GetRoot()[:])
					chain.Record(sigTree.GetRoot())
					cum = 0
				} else {
					chain.Hash(uint(entry.NumHashes))
				}
				if !bytes.Equal(entry.Hash[:], chain[:]) {
					klog.Errorf("PoH mismatch! expected %s, actual %s",
						entry.Hash, solana.Hash(chain))
					break replay
				}
			}
		}
	}
}
