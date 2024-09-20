package sealevel

import (
	"bytes"
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
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

func (sf *SysvarFees) Update(lamportsPerSignature uint64) {
	sf.FeeCalculator.LamportsPerSignature = lamportsPerSignature
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

func WriteFeesSysvar(accts *accounts.Accounts, fees SysvarFees) {
	feesSysvarAcct, err := (*accts).GetAccount(&SysvarFeesAddr)
	if err != nil {
		panic("failed to read Fees sysvar account")
	}

	data := new(bytes.Buffer)
	enc := bin.NewBinEncoder(data)

	err = enc.WriteUint64(fees.FeeCalculator.LamportsPerSignature, bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize LamportsPerSignature for Fees sysvar: %w", err)
		panic(err)
	}

	feesSysvarAcct.Data = data.Bytes()

	err = (*accts).SetAccount(&SysvarFeesAddr, feesSysvarAcct)
	if err != nil {
		err = fmt.Errorf("failed write newly serialized Fees sysvar to sysvar account: %w", err)
		panic(err)
	}
}
