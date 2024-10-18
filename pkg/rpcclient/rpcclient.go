package rpcclient

import (
	"github.com/gagliardetto/solana-go/rpc"
)

type RpcClient struct {
	client *rpc.Client
}

func NewRpcClient(endpoint string) *RpcClient {
	client := rpc.New(endpoint)
	return &RpcClient{client: client}
}
