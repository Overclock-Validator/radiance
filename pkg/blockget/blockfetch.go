package blockget

import (
	"context"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

type BlockFetcher struct {
	client *rpc.Client
}

func NewBlockFetcher(endpoint string) *BlockFetcher {
	client := rpc.New(endpoint)
	return &BlockFetcher{client: client}
}

func (fetcher *BlockFetcher) GetBlock(slot uint64) (*rpc.GetBlockResult, error) {
	return fetcher.client.GetBlock(context.TODO(), slot)
}

func (fetcher *BlockFetcher) GetBlockConfirmed(slot uint64) (*rpc.GetBlockResult, error) {
	includeRewards := false
	maxSupportedTxVer := uint64(0)

	result, err := fetcher.client.GetBlockWithOpts(
		context.TODO(),
		slot,
		&rpc.GetBlockOpts{
			MaxSupportedTransactionVersion: &maxSupportedTxVer,
			Encoding:                       solana.EncodingBase64,
			Commitment:                     rpc.CommitmentConfirmed,
			TransactionDetails:             rpc.TransactionDetailsFull,
			Rewards:                        &includeRewards,
		},
	)

	return result, err
}

func (fetcher *BlockFetcher) GetBlockFinalized(slot uint64) (*rpc.GetBlockResult, error) {
	includeRewards := false
	maxSupportedTxVer := uint64(0)

	result, err := fetcher.client.GetBlockWithOpts(
		context.TODO(),
		slot,
		&rpc.GetBlockOpts{
			MaxSupportedTransactionVersion: &maxSupportedTxVer,
			Commitment:                     rpc.CommitmentFinalized,
			TransactionDetails:             rpc.TransactionDetailsFull,
			Rewards:                        &includeRewards,
		},
	)

	return result, err
}

func (fetcher *BlockFetcher) GetLatestBlockConfirmed() (*rpc.GetBlockResult, error) {
	result, err := fetcher.client.GetLatestBlockhash(context.TODO(), rpc.CommitmentConfirmed)
	if err != nil {
		return nil, err
	}

	slot := result.Context.Slot

	return fetcher.GetBlockConfirmed(slot)
}

func (fetcher *BlockFetcher) GetLatestBlockFinalized() (*rpc.GetBlockResult, error) {
	result, err := fetcher.client.GetLatestBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		return nil, err
	}

	slot := result.Context.Slot

	return fetcher.GetBlockFinalized(slot)
}
