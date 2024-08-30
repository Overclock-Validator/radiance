package blockget

import (
	"fmt"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
)

func TestBlockFetch_Confirmed(t *testing.T) {
	fetcher := NewBlockFetcher("https://api.mainnet-beta.solana.com/")

	result, err := fetcher.GetBlockConfirmed(1234)
	assert.NoError(t, err)

	if len(result.Transactions) == 0 {
		fmt.Printf("no transactions")
	} else {
		fmt.Printf("block contained %d transactions.\n", len(result.Transactions))

		for _, tx := range result.Transactions {
			txParsed, err := tx.GetTransaction()
			assert.NoError(t, err)
			//fmt.Printf("%+v\n", txParsed)
			err = txParsed.VerifySignatures()
			assert.NoError(t, err)
		}
	}
}

func TestBlockFetch_Finalized(t *testing.T) {
	fetcher := NewBlockFetcher("https://api.mainnet-beta.solana.com/")

	result, err := fetcher.GetBlockFinalized(1234)
	assert.NoError(t, err)

	if len(result.Transactions) == 0 {
		fmt.Printf("no transactions")
	} else {
		fmt.Printf("block contained %d transactions.\n", len(result.Transactions))

		for _, tx := range result.Transactions {
			txParsed, err := tx.GetTransaction()
			assert.NoError(t, err)
			//fmt.Printf("%+v\n", txParsed)
			err = txParsed.VerifySignatures()
			assert.NoError(t, err)
		}
	}
}

func TestBlockFetch_LatestConfirmed(t *testing.T) {
	fetcher := NewBlockFetcher("https://api.mainnet-beta.solana.com/")

	result, err := fetcher.GetLatestBlockConfirmed()
	assert.NoError(t, err)

	fmt.Printf("slot: %d\n", *result.BlockHeight)

	if len(result.Transactions) == 0 {
		fmt.Printf("no transactions")
	} else {
		fmt.Printf("block contained %d transactions.\n", len(result.Transactions))

		for _, tx := range result.Transactions {
			txParsed, err := tx.GetTransaction()
			assert.NoError(t, err)
			//fmt.Printf("%+v\n", txParsed)
			err = txParsed.VerifySignatures()
			assert.NoError(t, err)
		}
	}
}

func TestBlockFetch_LatestFinalized(t *testing.T) {
	fetcher := NewBlockFetcher("https://api.mainnet-beta.solana.com/")

	result, err := fetcher.GetLatestBlockFinalized()
	assert.NoError(t, err)

	fmt.Printf("slot: %d\n", *result.BlockHeight)

	if len(result.Transactions) == 0 {
		fmt.Printf("no transactions")
	} else {
		fmt.Printf("block contained %d transactions.\n", len(result.Transactions))

		var numAccounts uint64
		allAccounts := make([]solana.PublicKey, 0)

		for _, tx := range result.Transactions {
			txParsed, err := tx.GetTransaction()
			assert.NoError(t, err)
			//fmt.Printf("%+v\n", txParsed)
			err = txParsed.VerifySignatures()
			assert.NoError(t, err)
			numAccounts += uint64(len(txParsed.Message.AccountKeys))
			allAccounts = append(allAccounts, txParsed.Message.AccountKeys...)
		}
		fmt.Printf("%d accounts in block\n", numAccounts)
		uniqAccts := lo.Uniq(allAccounts)
		fmt.Printf("unique accounts in block: %d\n", len(uniqAccts))
	}
}
