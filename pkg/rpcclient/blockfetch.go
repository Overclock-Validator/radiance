package rpcclient

import (
	"context"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

func (fetcher *RpcClient) GetBlock(slot uint64) (*rpc.GetBlockResult, error) {
	return fetcher.client.GetBlock(context.TODO(), slot)
}

func (fetcher *RpcClient) GetBlockConfirmed(slot uint64) (*rpc.GetBlockResult, error) {
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

func (fetcher *RpcClient) GetBlockFinalized(slot uint64) (*rpc.GetBlockResult, error) {
	includeRewards := true
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

func (fetcher *RpcClient) GetLatestBlockConfirmed() (*rpc.GetBlockResult, error) {
	result, err := fetcher.client.GetLatestBlockhash(context.TODO(), rpc.CommitmentConfirmed)
	if err != nil {
		return nil, err
	}

	slot := result.Context.Slot

	return fetcher.GetBlockConfirmed(slot)
}

func (fetcher *RpcClient) GetLatestBlockFinalized() (*rpc.GetBlockResult, error) {
	result, err := fetcher.client.GetLatestBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		return nil, err
	}

	slot := result.Context.Slot

	return fetcher.GetBlockFinalized(slot)
}

func (fetcher *RpcClient) GetLeaderForSlot(slot uint64) (solana.PublicKey, error) {
	leader, err := fetcher.client.GetSlotLeaders(context.TODO(), slot, 1)
	if err != nil {
		return solana.PublicKey{}, err
	}
	return leader[0], err
}
