package sealevel

import (
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
	"go.firedancer.io/radiance/pkg/global"
)

const SysvarFeesAddrStr = "SysvarFees111111111111111111111111111111111"

var SysvarFeesAddr = base58.MustDecodeFromString(SysvarFeesAddrStr)

const SysvarFeesStructLen = 8

type FeeCalculator struct {
	LamportsPerSignature uint64
}
type SysvarFees struct {
	FeeCalculator FeeCalculator
}

func (sf *SysvarFees) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {
	lamportsPerSignature, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read LamportsPerSignature when decoding SysvarFees: %w", err)
	}
	sf.FeeCalculator.LamportsPerSignature = lamportsPerSignature
	return
}

func (sf *SysvarFees) MustUnmarshalWithDecoder(decoder *bin.Decoder) {
	err := sf.UnmarshalWithDecoder(decoder)
	if err != nil {
		panic(err.Error())
	}
}

func ReadFeesSysvar(accts *accounts.Accounts) SysvarFees {
	feesSysvarAcct, err := (*accts).GetAccount(&SysvarFeesAddr)
	if err != nil {
		panic("failed to read fees sysvar account")
	}

	dec := bin.NewBinDecoder(feesSysvarAcct.Data)

	var fees SysvarFees
	fees.MustUnmarshalWithDecoder(dec)

	return fees
}

// TODO: implement logic for writing the epoch rewards sysvar and for creating a default
func UpdateFeesSysvar(globalCtx *global.GlobalCtx, newFees *SysvarFees) {

}
