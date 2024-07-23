package sealevel

import (
	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
)

const SysvarRecentBlockHashesAddrStr = "SysvarRecentB1ockHashes11111111111111111111"

var SysvarRecentBlockHashesAddr = base58.MustDecodeFromString(SysvarRecentBlockHashesAddrStr)

type RecentBlockHashesEntry struct {
	Blockhash     [32]byte
	FeeCalculator FeeCalculator
}

type SysvarRecentBlockhashes []RecentBlockHashesEntry

func (recentBlockhashes *SysvarRecentBlockhashes) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	numBlockhashes, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	for count := uint64(0); count < numBlockhashes; count++ {
		var recentBlockhashEntry RecentBlockHashesEntry
		hash, err := decoder.ReadBytes(32)
		if err != nil {
			return err
		}
		copy(recentBlockhashEntry.Blockhash[:], hash)

		recentBlockhashEntry.FeeCalculator.LamportsPerSignature, err = decoder.ReadUint64(bin.LE)
		if err != nil {
			return err
		}

		*recentBlockhashes = append(*recentBlockhashes, recentBlockhashEntry)
	}

	return nil
}

func (recentBlockhashes *SysvarRecentBlockhashes) MarshalWithEncoder(encoder *bin.Encoder) error {
	numBlockhashes := uint64(len(*recentBlockhashes))

	err := encoder.WriteUint64(numBlockhashes, bin.LE)
	if err != nil {
		return err
	}

	rbh := *recentBlockhashes
	for count := uint64(0); count < numBlockhashes; count++ {
		err = encoder.WriteBytes(rbh[count].Blockhash[:], false)
		if err != nil {
			return err
		}

		err = encoder.WriteUint64(rbh[count].FeeCalculator.LamportsPerSignature, bin.LE)
		if err != nil {
			return err
		}
	}

	return nil
}

func CheckAcctForRecentBlockHashesSysvar(txCtx *TransactionCtx, instrCtx *InstructionCtx, instrAcctIdx uint64) error {
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

func (recentBlockhashes *SysvarRecentBlockhashes) MustUnmarshalWithDecoder(decoder *bin.Decoder) {
	err := recentBlockhashes.UnmarshalWithDecoder(decoder)
	if err != nil {
		panic(err.Error())
	}
}

func (recentBlockhashes *SysvarRecentBlockhashes) GetLatest() RecentBlockHashesEntry {
	rbh := *recentBlockhashes
	return rbh[len(rbh)-1]
}

func ReadRecentBlockHashesSysvar(accts *accounts.Accounts) (SysvarRecentBlockhashes, error) {
	recentBlockhashesAcct, err := (*accts).GetAccount(&SysvarRecentBlockHashesAddr)
	if err != nil {
		return SysvarRecentBlockhashes{}, InstrErrUnsupportedSysvar
	}

	if recentBlockhashesAcct.Lamports == 0 || len(recentBlockhashesAcct.Data) == 0 {
		return SysvarRecentBlockhashes{}, InstrErrUnsupportedSysvar
	}

	dec := bin.NewBinDecoder(recentBlockhashesAcct.Data)

	var recentBlockhashes SysvarRecentBlockhashes
	err = recentBlockhashes.UnmarshalWithDecoder(dec)
	if err != nil {
		return SysvarRecentBlockhashes{}, InstrErrUnsupportedSysvar
	}

	return recentBlockhashes, nil
}

func ReadRecentBlockHashesSysvarFromCache(execCtx *ExecutionCtx, instrCtx *InstructionCtx, instrAcctIdx uint64) (*SysvarRecentBlockhashes, error) {
	err := CheckAcctForRecentBlockHashesSysvar(execCtx.TransactionContext, instrCtx, instrAcctIdx)
	if err != nil {
		return nil, err
	}
	return execCtx.SysvarCache.GetRecentBlockHashes(), nil
}
