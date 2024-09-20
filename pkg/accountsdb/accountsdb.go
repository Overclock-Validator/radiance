package accountsdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/Overclock-Validator/sniper"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/accounts"
)

type AccountsDb struct {
	indexDb       *sniper.Store
	acctsDir      string
	indexDir      string
	largestFileId atomic.Uint64
	bankHash      [32]byte
}

var (
	ErrNoAccount = errors.New("ErrNoAccount")
)

func OpenDb(accountsDbDir string) (*AccountsDb, error) {

	// check for existence of the 'accounts' directory, which holds the appendvecs
	appendVecsDir := fmt.Sprintf("%s/accounts", accountsDbDir)
	_, err := os.Stat(appendVecsDir)
	if err != nil {
		return nil, err
	}

	// attempt to open largest_file_id file
	largestFileIdFn := fmt.Sprintf("%s/largest_file_id", accountsDbDir)
	lfi, err := os.Open(largestFileIdFn)
	if err != nil {
		fmt.Printf("failed to open %s\n", largestFileIdFn)
		return nil, err
	}

	largestFileIdBytes := make([]byte, 8)
	bytesRead, err := lfi.Read(largestFileIdBytes)
	if err != nil {
		fmt.Printf("error reading %s: %s\n", largestFileIdFn, err)
		return nil, err
	} else if bytesRead != 8 {
		fmt.Printf("error reading %s: expected 8 bytes, got %d\n", largestFileIdFn, bytesRead)
		return nil, fmt.Errorf("only got %d bytes", bytesRead)
	}

	largestFileId := binary.LittleEndian.Uint64(largestFileIdBytes)

	//////
	// attempt to open largest_file_id file
	bankHashFn := fmt.Sprintf("%s/bank_hash", accountsDbDir)
	bhf, err := os.Open(bankHashFn)
	if err != nil {
		fmt.Printf("failed to open %s\n", bankHashFn)
		return nil, err
	}

	bankHashBytes := make([]byte, 32)
	bytesRead, err = bhf.Read(bankHashBytes)
	if err != nil {
		fmt.Printf("error reading %s: %s\n", bankHashFn, err)
		return nil, err
	} else if bytesRead != 32 {
		fmt.Printf("error reading %s: expected 8 bytes, got %d\n", bankHashFn, bytesRead)
		return nil, fmt.Errorf("only got %d bytes", bytesRead)
	}

	// attempt to open the index kv store
	indexDir := fmt.Sprintf("%s/index", accountsDbDir)
	db, err := sniper.Open(sniper.Dir(indexDir))
	if err != nil {
		fmt.Printf("failed to open database: %s\n", err)
		return nil, err
	}

	accountsDb := &AccountsDb{indexDb: db, acctsDir: appendVecsDir, indexDir: indexDir}
	accountsDb.largestFileId.Store(largestFileId)
	copy(accountsDb.bankHash[:], bankHashBytes)

	return accountsDb, nil
}

func (accountsDb *AccountsDb) CloseDb() {
	accountsDb.indexDb.Close()
}

func (accountsDb *AccountsDb) GetAccount(pubkey solana.PublicKey) (*accounts.Account, error) {
	acctIdxEntryBytes, err := accountsDb.indexDb.Get(pubkey[:])
	if err != nil {
		return nil, ErrNoAccount
	}

	acctIdxEntry, err := unmarshalAcctIdxEntry(acctIdxEntryBytes)
	if err != nil {
		panic("failed to unmarshal AccountIndexEntry from index kv database")
	}

	appendVecFileName := fmt.Sprintf("%s/%d.%d", accountsDb.acctsDir, acctIdxEntry.Slot, acctIdxEntry.FileId)
	appendVecFile, err := os.Open(appendVecFileName)
	if err != nil {
		return nil, err
	}
	defer appendVecFile.Close()

	offset, err := appendVecFile.Seek(int64(acctIdxEntry.Offset), 0)
	if err != nil {
		panic(fmt.Sprintf("file seek failed: %s\n", err))
	}
	if offset != int64(acctIdxEntry.Offset) {
		panic(fmt.Sprintf("file seek gave wrong idx (%d)\n", offset))
	}

	acct, err := unmarshalAcctFromAppendVecAcctHeader(appendVecFile)
	if err != nil {
		panic(fmt.Sprintf("failed to unmarshal account from appendvec file %s: %s", appendVecFileName, err))
	}

	if acct.Key != pubkey {
		panic(fmt.Sprintf("account unmarshaled from appendvec file %s has the wrong pubkey", appendVecFileName))
	}

	return acct, err
}

func (accountsDb *AccountsDb) StoreAccounts(accts []*accounts.Account, slot uint64) error {
	fileId := accountsDb.largestFileId.Add(1)

	appendVecFileName := fmt.Sprintf("%s/%d.%d", accountsDb.acctsDir, slot, fileId)
	appendVecFile, err := os.OpenFile(appendVecFileName, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer appendVecFile.Close()

	// allocate required memory all at once to avoid constant reallocs
	marshaledSize := appendVecAcctsMarshaledSize(accts)
	appendVecAcctsBuf := new(bytes.Buffer)
	appendVecAcctsBuf.Grow(int(marshaledSize))

	indexWriter := new(bytes.Buffer)
	indexWriter.Grow(24)
	indexEncoder := bin.NewBinEncoder(indexWriter)

	for _, acct := range accts {

		// create index entry, encode it and write it to the index kv store
		// offset field is specified as the current num of bytes written to the appendvec buffer.
		indexWriter.Reset()
		indexEntry := AccountIndexEntry{Slot: slot, FileId: fileId, Offset: uint64(appendVecAcctsBuf.Len())}

		err = indexEntry.MarshalWithEncoder(indexEncoder)
		if err != nil {
			return err
		}

		err = accountsDb.indexDb.Set(acct.Key[:], indexWriter.Bytes(), 0)
		if err != nil {
			return err
		}

		// marshal up the account as an appendvec style account and write it to the buffer
		appendVecAcct := AppendVecAccount{DataLen: uint64(len(acct.Data)), Pubkey: acct.Key, Lamports: acct.Lamports,
			RentEpoch: acct.RentEpoch, Owner: acct.Owner, Executable: acct.Executable, Data: acct.Data}

		err = appendVecAcct.Marshal(appendVecAcctsBuf)
		if err != nil {
			return err
		}
	}

	// write the appendvecs data into the file
	n, err := appendVecFile.Write(appendVecAcctsBuf.Bytes())
	if err != nil {
		return err
	} else if n != appendVecAcctsBuf.Len() {
		return fmt.Errorf("only wrote %d appendvec account bytes, rather than %d", n, appendVecAcctsBuf.Len())
	}

	return nil
}

func (accountsDb *AccountsDb) BankHash() [32]byte {
	return accountsDb.bankHash
}
