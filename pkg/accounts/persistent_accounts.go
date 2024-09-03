package accounts

import (
	"bytes"
	"fmt"

	bin "github.com/gagliardetto/binary"
	"github.com/lotusdblabs/lotusdb/v2"
	//"github.com/lotusdblabs/lotusdb/v2"
	"go.firedancer.io/radiance/pkg/base58"
)

type PersistentAccountsDb struct {
	db *lotusdb.DB
}

func CreateNewAccountsDb(filename string) (*PersistentAccountsDb, error) {
	options := lotusdb.DefaultOptions
	options.DirPath = filename

	db, err := lotusdb.Open(options)
	if err != nil {
		return nil, err
	}

	return &PersistentAccountsDb{db: db}, nil
}

func (m PersistentAccountsDb) GetAccount(pubkey *[32]byte) (*Account, error) {
	acctBytes, err := m.db.Get(pubkey[:])

	if err != nil {
		return nil, fmt.Errorf("error whilst retrieving account %s: %s", base58.Encode(pubkey[:]), err)
	}

	decoder := bin.NewBinDecoder(acctBytes)
	acct := new(Account)

	err = acct.UnmarshalWithDecoder(decoder)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize account from pebble accountsdb")
	}

	return acct, nil
}

func (m PersistentAccountsDb) SetAccount(pubkey *[32]byte, acct *Account) error {
	writer := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(writer)

	err := acct.MarshalWithEncoder(encoder)
	if err != nil {
		return fmt.Errorf("failed to serialize account for storage in pebble accountsdb")
	}

	acctBytes := writer.Bytes()

	err = m.db.Put(pubkey[:], acctBytes)
	if err != nil {
		return fmt.Errorf("error setting account for %s: %s", base58.Encode(pubkey[:]), err)
	}

	return nil
}

func (m PersistentAccountsDb) SlotForAcct(pubkey *[32]byte) (uint64, error) {
	acctBytes, err := m.db.Get(pubkey[:])

	if err != nil {
		return 0, fmt.Errorf("error whilst retrieving account %s: %s", base58.Encode(pubkey[:]), err)
	}

	decoder := bin.NewBinDecoder(acctBytes)
	var slot uint64
	slot, err = decoder.ReadUint64(bin.LE)

	return slot, err
}
