package replay

import (
	"fmt"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/accountsdb"
	"go.firedancer.io/radiance/pkg/sealevel"
	"k8s.io/klog/v2"
)

type Block struct {
	Slot            uint64
	Transactions    []*solana.Transaction
	BankHash        [32]byte
	ParentBankhash  [32]byte
	NumSignatures   uint64
	RecentBlockhash [32]byte
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

	for _, tx := range block.Transactions {
		if !tx.Message.IsVersioned() {
			continue
		}

		for _, addrTableKey := range tx.Message.GetAddressTableLookups().GetTableIDs() {
			acct, err := accountsDb.GetAccount(addrTableKey)
			if err != nil {
				return err
			}

			addrLookupTable, err := sealevel.UnmarshalAddressLookupTable(acct.Data)
			if err != nil {
				return err
			}

			tables[addrTableKey] = addrLookupTable.Addresses
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

func loadBlockAccounts(accountsDb *accountsdb.AccountsDb, block *Block) (accounts.Accounts, error) {
	err := resolveAddrTableLookups(accountsDb, block)
	if err != nil {
		return nil, err
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
				acct = &accounts.Account{Key: pk, Owner: sealevel.NativeLoaderAddr, Executable: true}
				klog.Infof("no account: %s, using empty owned by Native Loader\n", pk)
			} else {
				acct = &accounts.Account{Key: pk, Owner: sealevel.SystemProgramAddr}
				klog.Infof("no account: %s, using empty owned by System program\n", pk)
			}
		} else if err != nil {
			return nil, err
		} else {
			klog.Infof("found account in loadBlockAccounts for: %s\n", acct.Key)
		}

		var pkBytes [32]byte
		copy(pkBytes[:], pk.Bytes())

		err = accts.SetAccount(&pkBytes, acct)
		if err != nil {
			return nil, err
		}
	}

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

			// update slothashes sysvar
			if sysvarAcct.Key == sealevel.SysvarSlotHashesAddr {
				decoder := bin.NewBinDecoder(sysvarAcct.Data)
				var slotHashes sealevel.SysvarSlotHashes
				err = slotHashes.UnmarshalWithDecoder(decoder)
				if err != nil {
					panic(fmt.Sprintf("unable to unmarshal slothashes sysvar"))
				}
				slotHashes.Update(block.Slot, block.BankHash)
				newSlotHashesBytes := slotHashes.MustMarshal()
				copy(sysvarAcct.Data, newSlotHashesBytes)
			}

			var sysvarPkBytes [32]byte
			copy(sysvarPkBytes[:], sysvarAddr.Bytes())
			err = accts.SetAccount(&sysvarPkBytes, sysvarAcct)
			if err != nil {
				panic(fmt.Sprintf("unable to set sysvar %s to accountsdb", sysvarAddr))
			}
		}
	}

	return accts, nil
}

func ProcessBlock(acctsDb *accountsdb.AccountsDb, block *Block, updateAcctsDb bool) ([]byte, error) {

	// gather up all accounts used by the block and put them into a SlotCtx object
	accts, err := loadBlockAccounts(acctsDb, block)
	if err != nil {
		return nil, err
	}

	slotCtx := &sealevel.SlotCtx{Slot: block.Slot, Accounts: accts, AccountsDb: acctsDb, Replay: true}

	// process & execute each transaction in turn
	for idx, tx := range block.Transactions {
		klog.Infof("******** executing transaction %d", idx+1)
		txErr := ProcessTransaction(slotCtx, tx)
		if txErr != nil {
			klog.Infof("tx %d returned error: %s\n", idx+1, txErr)
		}
	}

	// after execution of all tx's in the block, slotCtx will now contain the new account states
	// in ModifiedAccounts, hence commit these updated states to accountsdb
	if updateAcctsDb {
		klog.Infof("updating accountsdb")
		if len(slotCtx.ModifiedAccts) > 0 {
			err = acctsDb.StoreAccounts(slotCtx.ModifiedAccts, slotCtx.Slot)
		}
	} else {
		klog.Infof("accountsdb not updated")
	}

	//acctDeltaHash := calculateAcctsDeltaHash(slotCtx.ModifiedAccts)

	// calculate bankhash
	//bankHash := calculateBankHash(acctDeltaHash, block.ParentBankhash, block.NumSignatures, block.RecentBlockhash)

	return nil, err
}
