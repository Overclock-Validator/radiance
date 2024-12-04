package replay

import (
	"fmt"
	"math"

	"github.com/Overclock-Validator/mithril/pkg/accounts"
	"github.com/Overclock-Validator/mithril/pkg/accountsdb"
	"github.com/Overclock-Validator/mithril/pkg/base58"
	"github.com/Overclock-Validator/mithril/pkg/features"
	"github.com/Overclock-Validator/mithril/pkg/fees"
	"github.com/Overclock-Validator/mithril/pkg/rent"
	"github.com/Overclock-Validator/mithril/pkg/rpcclient"
	"github.com/Overclock-Validator/mithril/pkg/sealevel"
	"github.com/Overclock-Validator/mithril/pkg/snapshot"
	"github.com/Overclock-Validator/mithril/pkg/util"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"k8s.io/klog/v2"
)

type BlockRewardsInfo struct {
	Leader      solana.PublicKey
	Lamports    uint64
	PostBalance uint64
}

type Block struct {
	Slot             uint64
	Transactions     []*solana.Transaction
	BankHash         [32]byte
	ParentBankhash   [32]byte
	NumSignatures    uint64
	Blockhash        [32]byte
	ExpectedBankhash [32]byte
	Manifest         *snapshot.SnapshotManifest
	TxMetas          []*rpc.TransactionMeta
	Leader           solana.PublicKey
	Reward           BlockRewardsInfo
	RecentBlockhash  [32]byte
}

func numBlockAccts(block *Block) uint64 {
	var numAccts uint64
	for _, tx := range block.Transactions {
		numAccts += uint64(len(tx.Message.AccountKeys))
	}
	return numAccts
}

func resolveAddrTableLookups(accountsDb *accountsdb.AccountsDb, block *Block) error {
	tables := make(map[solana.PublicKey]solana.PublicKeySlice)

	for idx, tx := range block.Transactions {
		klog.Infof("resolveAddrTableLookups for transaction %d", idx)

		if !tx.Message.IsVersioned() {
			continue
		}

		var skipLookup bool
		for _, addrTableKey := range tx.Message.GetAddressTableLookups().GetTableIDs() {
			acct, err := accountsDb.GetAccount(addrTableKey)
			if err != nil {
				klog.Infof("unable to get address lookup table account: %s", addrTableKey)
				skipLookup = true
				break
			}

			addrLookupTable, err := sealevel.UnmarshalAddressLookupTable(acct.Data)
			if err != nil {
				return err
			}

			tables[addrTableKey] = addrLookupTable.Addresses
		}

		if skipLookup {
			continue
		}

		err := tx.Message.SetAddressTables(tables)
		if err != nil {
			return err
		}

		err = tx.Message.ResolveLookups()
		if err != nil {
			return err
		}
	}

	return nil
}

func extractAndDedupeBlockAccts(block *Block) []solana.PublicKey {
	pubkeys := make([]solana.PublicKey, 0)

	for _, tx := range block.Transactions {
		for _, pubkey := range tx.Message.AccountKeys {
			pubkeys = append(pubkeys, pubkey)
		}
	}

	pubkeys = util.DedupePubkeys(pubkeys)

	return pubkeys
}

func isNativeProgram(pubkey solana.PublicKey) bool {
	if pubkey == sealevel.SystemProgramAddr || pubkey == sealevel.BpfLoaderUpgradeableAddr ||
		pubkey == sealevel.BpfLoader2Addr || pubkey == sealevel.BpfLoaderDeprecatedAddr ||
		pubkey == sealevel.VoteProgramAddr || pubkey == sealevel.StakeProgramAddr ||
		pubkey == sealevel.AddressLookupTableAddr || pubkey == sealevel.ConfigProgramAddr ||
		pubkey == sealevel.ComputeBudgetProgramAddr {
		return true
	} else {
		return false
	}
}

func isSysvar(pubkey solana.PublicKey) bool {
	if pubkey == sealevel.SysvarClockAddr || pubkey == sealevel.SysvarEpochRewardsAddr ||
		pubkey == sealevel.SysvarEpochScheduleAddr || pubkey == sealevel.SysvarFeesAddr ||
		pubkey == sealevel.SysvarInstructionsAddr || pubkey == sealevel.SysvarLastRestartSlotAddr ||
		pubkey == sealevel.SysvarRecentBlockHashesAddr || pubkey == sealevel.SysvarRentAddr ||
		pubkey == sealevel.SysvarSlotHashesAddr || pubkey == sealevel.SysvarSlotHistoryAddr ||
		pubkey == sealevel.SysvarStakeHistoryAddr {
		return true
	} else {
		return false
	}
}

func loadBlockAccountsAndUpdateSysvars(accountsDb *accountsdb.AccountsDb, block *Block) (accounts.Accounts, uint64, error) {
	err := resolveAddrTableLookups(accountsDb, block)
	if err != nil {
		return nil, 0, err
	}

	dedupedAccts := extractAndDedupeBlockAccts(block)
	accts := accounts.NewMemAccounts()

	for _, pk := range dedupedAccts {
		// retrieve account from accountsdb

		acct, err := accountsDb.GetAccount(pk)

		// add the account to the slice, add a 'blank' account if the account doesn't exist,
		// or return an error
		if err == accountsdb.ErrNoAccount {
			if isNativeProgram(pk) {
				acct = &accounts.Account{Key: pk, Owner: sealevel.NativeLoaderAddr, Executable: true, Lamports: 1}
				klog.Infof("no account: %s, using empty owned by Native Loader\n", pk)
			} else {
				acct = &accounts.Account{Key: pk, Owner: sealevel.SystemProgramAddr, RentEpoch: math.MaxUint64}
				klog.Infof("no account: %s, using empty owned by System program\n", pk)
			}
		} else if err != nil {
			return nil, 0, err
		} else {
			klog.Infof("found account in loadBlockAccounts for: %s\n", acct.Key)
		}

		var pkBytes [32]byte
		copy(pkBytes[:], pk.Bytes())

		err = accts.SetAccount(&pkBytes, acct)
		if err != nil {
			return nil, 0, err
		}
	}

	var epoch uint64

	// load sysvar accounts
	{
		sysvarAddrs := []solana.PublicKey{sealevel.SysvarClockAddr /*sealevel.SysvarEpochRewardsAddr,*/, sealevel.SysvarEpochScheduleAddr,
			sealevel.SysvarFeesAddr, sealevel.SysvarRecentBlockHashesAddr, sealevel.SysvarRentAddr, sealevel.SysvarSlotHashesAddr,
			sealevel.SysvarSlotHistoryAddr, sealevel.SysvarStakeHistoryAddr}

		for _, sysvarAddr := range sysvarAddrs {
			sysvarAcct, err := accountsDb.GetAccount(sysvarAddr)
			if err != nil {
				panic(fmt.Sprintf("unable to retrieve sysvar %s from accountsdb", sysvarAddr))
			}

			if sysvarAcct.Key == sealevel.SysvarSlotHashesAddr {
				decoder := bin.NewBinDecoder(sysvarAcct.Data)
				var slotHashes sealevel.SysvarSlotHashes

				err = slotHashes.UnmarshalWithDecoder(decoder)
				if err != nil {
					panic(fmt.Sprintf("unable to unmarshal slothashes sysvar"))
				}

				slotHashes.Update(block.Slot, block.ParentBankhash)
				newSlotHashesBytes := slotHashes.MustMarshal()
				copy(sysvarAcct.Data, newSlotHashesBytes)
			} else if sysvarAcct.Key == sealevel.SysvarClockAddr {
				decoder := bin.NewBinDecoder(sysvarAcct.Data)
				var clock sealevel.SysvarClock

				err = clock.UnmarshalWithDecoder(decoder)
				if err != nil {
					panic(fmt.Sprintf("unable to unmarshal clock sysvar"))
				}

				err = updateClockSysvar(&clock, accountsDb, block)
				if err != nil {
					panic(fmt.Sprintf("failed to update clock sysvar: %s", err))
				}

				newClockBytes := clock.MustMarshal()
				copy(sysvarAcct.Data, newClockBytes)
				epoch = clock.Epoch
			}

			var sysvarPkBytes [32]byte
			copy(sysvarPkBytes[:], sysvarAddr.Bytes())
			err = accts.SetAccount(&sysvarPkBytes, sysvarAcct)
			if err != nil {
				panic(fmt.Sprintf("unable to set sysvar %s to accountsdb", sysvarAddr))
			}
		}
	}

	return accts, epoch, nil
}

func scanAndEnableFeatures(acctsDb *accountsdb.AccountsDb, slot uint64) *features.Features {
	f := features.NewFeaturesDefault()
	for _, featureGate := range features.AllFeatureGates {
		_, err := acctsDb.GetAccount(featureGate.Address)
		if err == nil {
			klog.Infof("enabled feature: %s, %s", featureGate.Name, solana.PublicKeyFromBytes(featureGate.Address[:]))
			f.EnableFeature(featureGate, slot)
		}
	}
	return f
}

func newBlockFromBlockResult(blockResult *rpc.GetBlockResult) (*Block, error) {
	block := new(Block)

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

func ReplayBlocks(acctsDb *accountsdb.AccountsDb, snapshotManifest *snapshot.SnapshotManifest, startSlot, endSlot int64, updateAcctsDb bool) error {
	var bankHash []byte

	rpcc := rpcclient.NewRpcClient("https://api.mainnet-beta.solana.com")

	for slot := int64(startSlot); slot <= endSlot; slot++ {

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

		if slot == startSlot {
			block.ParentBankhash = snapshotManifest.Bank.Hash
		} else {
			copy(block.ParentBankhash[:], bankHash)
		}

		block.Manifest = snapshotManifest
		block.Leader = leader
		block.Reward = BlockRewardsInfo{Leader: blockResult.Rewards[0].Pubkey, Lamports: uint64(blockResult.Rewards[0].Lamports), PostBalance: blockResult.Rewards[0].PostBalance}

		bankHash, err = ProcessBlock(acctsDb, block, updateAcctsDb)
		if err != nil {
			klog.Errorf("error encountered during block replay: %s\n", err)
			break
		} else {
			klog.Infof("block replayed successfully.\n")
		}
	}

	return nil
}

func ProcessBlock(acctsDb *accountsdb.AccountsDb, block *Block, updateAcctsDb bool) ([]byte, error) {

	// gather up all accounts referenced in the block
	accts, epoch, err := loadBlockAccountsAndUpdateSysvars(acctsDb, block)
	if err != nil {
		return nil, err
	}

	oldAccts := make([]accounts.Account, 0)
	for _, a := range accts.AllAccounts() {
		oldAccts = append(oldAccts, *a)
	}

	f := scanAndEnableFeatures(acctsDb, block.Slot)

	slotCtx := &sealevel.SlotCtx{Slot: block.Slot, Epoch: epoch, ParentSlot: block.Slot - 1, Blockhash: block.Blockhash, RecentBlockhash: block.RecentBlockhash, Accounts: accts, AccountsDb: acctsDb, Replay: true, Features: f}
	slotCtx.ModifiedAccts = make(map[solana.PublicKey]bool)

	var totalTxFees uint64
	acctIsWritable := make(map[solana.PublicKey]bool)

	// process & execute each transaction in turn
	for idx, tx := range block.Transactions {
		klog.Infof("[+] executing transaction %d, %s", idx+1, tx.Signatures[0])
		txFee, wpks, txErr := ProcessTransaction(slotCtx, tx, block.TxMetas[idx])
		if txErr != nil {
			klog.Infof("tx %d returned error: %s\n", idx+1, txErr)
		}

		// check for success-failure return value divergences
		if txErr == nil && block.TxMetas[idx].Err != nil {
			klog.Infof("tx %s return value divergence: txErr was nil, but onchain err was %+v", tx.Signatures[0], block.TxMetas[idx].Err)
		} else if txErr != nil && block.TxMetas[idx].Err == nil {
			klog.Infof("tx %s return value divergence: txErr was %+v, but onchain err was nil", tx.Signatures[0], txErr)
		}

		for _, pk := range wpks {
			acctIsWritable[pk] = true
		}

		totalTxFees += txFee
	}

	// distribute tx fees to the leader by calculating 50% of the tx fees and adding the sum
	// to the slot leader's lamports balance, subsequently including it in the accounts delta hash.
	fees.DistributeTxFeesToSlotLeader(acctsDb, slotCtx, block.Leader, totalTxFees)

	klog.Infof("from RPC fees for leader: %d, post-balance: %d (%s)", block.Reward.Lamports, block.Reward.PostBalance, block.Reward.Leader)

	epochScheduleAcct, err := slotCtx.Accounts.GetAccount(&sealevel.SysvarEpochScheduleAddr)
	if err != nil {
		panic("unable to fetch EpochSchedule sysvar account")
	}

	dec := bin.NewBinDecoder(epochScheduleAcct.Data)
	var epochSchedule sealevel.SysvarEpochSchedule
	err = epochSchedule.UnmarshalWithDecoder(dec)
	if err != nil {
		panic("unable to deserialize EpochSchedule sysvar")
	}

	rentSysvarAcct, err := slotCtx.Accounts.GetAccount(&sealevel.SysvarRentAddr)
	if err != nil {
		panic("unable to fetch EpochSchedule sysvar account")
	}

	dec = bin.NewBinDecoder(rentSysvarAcct.Data)
	var rentSysvar sealevel.SysvarRent
	err = rentSysvar.UnmarshalWithDecoder(dec)
	if err != nil {
		panic("unable to deserialize Rent sysvar")
	}

	rentAccts := rent.CollectRentEagerly(slotCtx, &rentSysvar, &epochSchedule)

	acctIsWritable[block.Leader] = true

	eligibleAccts := make([]*accounts.Account, 0)
	for pk := range acctIsWritable {
		acct, _ := slotCtx.GetAccount(pk)
		eligibleAccts = append(eligibleAccts, acct)
	}

	eligibleAccts = append(eligibleAccts, rentAccts...)
	sysvarAccts := collectAndUpdateSysvarAcctsForAdh(slotCtx)
	eligibleAccts = append(eligibleAccts, sysvarAccts...)

	if len(eligibleAccts) > 0 && updateAcctsDb {
		klog.Infof("updating accountsdb")
		err = acctsDb.StoreAccounts(eligibleAccts, slotCtx.Slot)
	} else {
		klog.Infof("accountsdb not updated")
	}

	klog.Infof("calculating accts delta hash for %d eligible accounts. len of rentAccts = %d", len(eligibleAccts), len(rentAccts))

	acctDeltaHash := calculateAcctsDeltaHash(eligibleAccts)

	// calculate bankhash
	bankHash := calculateBankHash(slotCtx, acctDeltaHash, block.ParentBankhash, block.NumSignatures, block.Blockhash)
	klog.Infof("calculated bankhash for slot %d was %s", block.Slot, base58.Encode(bankHash))

	return bankHash, err
}
