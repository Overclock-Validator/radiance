package replay

import (
	"bytes"
	"fmt"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/accountsdb"
	"go.firedancer.io/radiance/pkg/base58"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/fees"
	"go.firedancer.io/radiance/pkg/sealevel"
	"go.firedancer.io/radiance/pkg/snapshot"
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
	seen := make(map[solana.PublicKey]bool)
	pubkeys := make([]solana.PublicKey, numBlockAccts(block))
	var pkCount uint64

	for _, tx := range block.Transactions {
		for _, pubkey := range tx.Message.AccountKeys {
			_, alreadySeen := seen[pubkey]
			if !alreadySeen {
				seen[pubkey] = true
				pubkeys[pkCount] = pubkey
				pkCount++
			}
		}
	}

	return pubkeys[:pkCount]
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
				acct = &accounts.Account{Key: pk, Owner: sealevel.SystemProgramAddr}
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

func ProcessBlock(acctsDb *accountsdb.AccountsDb, block *Block, updateAcctsDb bool) error {

	// gather up all accounts used by the block and put them into a SlotCtx object
	accts, epoch, err := loadBlockAccountsAndUpdateSysvars(acctsDb, block)
	if err != nil {
		return err
	}

	f := scanAndEnableFeatures(acctsDb, block.Slot)

	slotCtx := &sealevel.SlotCtx{Slot: block.Slot, Epoch: epoch, ParentSlot: block.Manifest.Bank.ParentSlot, Accounts: accts, AccountsDb: acctsDb, Replay: true, Features: f}
	slotCtx.ModifiedAccts = make(map[solana.PublicKey]bool)

	var totalTxFees uint64

	// process & execute each transaction in turn
	for idx, tx := range block.Transactions {
		klog.Infof("[+] executing transaction %d, %s", idx+1, tx.Signatures[0])
		txFee, txErr := ProcessTransaction(slotCtx, tx, block.TxMetas[idx])
		if txErr != nil {
			klog.Infof("tx %d returned error: %s\n", idx+1, txErr)
		}

		// check for success-failure return value divergences
		if txErr == nil && block.TxMetas[idx].Err != nil {
			klog.Infof("tx %s return value divergence: txErr was nil, but onchain err was %+v", tx.Signatures[0], block.TxMetas[idx].Err)
		} else if txErr != nil && block.TxMetas[idx].Err == nil {
			klog.Infof("tx %s return value divergence: txErr was %+v, but onchain err was nil", tx.Signatures[0], txErr)
		}

		totalTxFees += txFee
	}

	// apply account state updates to accountsdb and collect the account states for inclusion
	// into the accounts delta hash and therefore the bankhash
	modifiedAccts := make([]*accounts.Account, 0)

	// distribute tx fees to the leader by calculating 50% of the tx fees and adding the sum
	// to the slot leader's lamports balance, subsequently including it in the accounts delta hash.
	fees.DistributeTxFees(acctsDb, slotCtx, block.Leader, totalTxFees)

	klog.Infof("from RPC fees for leader: %d, post-balance: %d (%s)", block.Reward.Lamports, block.Reward.PostBalance, block.Reward.Leader)

	for pk := range slotCtx.ModifiedAccts {
		acct, err := slotCtx.Accounts.GetAccount((*[32]byte)(pk.Bytes()))
		if err != nil {
			panic("unable to get account for state update")
		}
		modifiedAccts = append(modifiedAccts, acct)
	}

	if len(modifiedAccts) > 0 && updateAcctsDb {
		klog.Infof("updating accountsdb")
		err = acctsDb.StoreAccounts(modifiedAccts, slotCtx.Slot)
	} else {
		klog.Infof("accountsdb not updated")
	}

	klog.Infof("calculating accts delta hash for %d modified accounts", len(modifiedAccts))

	acctDeltaHash := calculateAcctsDeltaHash(modifiedAccts)

	// calculate bankhash
	bankHash := calculateBankHash(slotCtx, acctDeltaHash, block.ParentBankhash, block.NumSignatures, block.Blockhash)
	if bytes.Equal(bankHash, block.ExpectedBankhash[:]) {
		klog.Infof("calculated bankhash matched expected bankhash.")
	} else {
		klog.Infof("calculated bankhash (%s) mismatch (%s)", base58.Encode(bankHash), base58.Encode(block.ExpectedBankhash[:]))
	}

	return err
}
