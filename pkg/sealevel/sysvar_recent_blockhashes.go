package sealevel

import (
	"go.firedancer.io/radiance/pkg/base58"
)

const SysvarRecentBlockHashesAddrStr = "SysvarRecentB1ockHashes11111111111111111111"

var SysvarRecentBlockHashesAddr = base58.MustDecodeFromString(SysvarRecentBlockHashesAddrStr)

type RecentBlockHashesEntry struct {
	Blockhash     [32]byte
	FeeCalculator FeeCalculator
}

type SysvarRecentBlockhashes []RecentBlockHashesEntry

func checkAcctForRecentBlockHashesSysvar(txCtx *TransactionCtx, instrCtx *InstructionCtx, instrAcctIdx uint64) error {
	idxInTx, err := instrCtx.IndexOfInstructionAccountInTransaction(instrAcctIdx)
	if err != nil {
		return err
	}
	pk, err := txCtx.KeyOfAccountAtIndex(idxInTx)
	if err != nil {
		return err
	}
	if pk == SysvarRecentBlockHashesAddr {
		return nil
	} else {
		return InstrErrInvalidArgument
	}
}

func ReadRecentBlockHashesSysvar(execCtx *ExecutionCtx, instrCtx *InstructionCtx, instrAcctIdx uint64) (*SysvarRecentBlockhashes, error) {
	err := checkAcctForRecentBlockHashesSysvar(execCtx.TransactionContext, instrCtx, instrAcctIdx)
	if err != nil {
		return nil, err
	}
	return execCtx.SysvarCache.RecentBlockHashes(), nil
}
