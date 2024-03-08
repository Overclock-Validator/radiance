package sealevel

import (
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
	"go.firedancer.io/radiance/pkg/global"
)

const SysvarRentAddrStr = "SysvarRent111111111111111111111111111111111"

var SysvarRentAddr = base58.MustDecodeFromString(SysvarRentAddrStr)

const SysvarRentStructLen = 17

type SysvarRent struct {
	LamportsPerUint8Year uint64
	ExemptionThreshold   float64
	BurnPercent          byte
}

func (sr *SysvarRent) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {
	lamportsPerUint8Year, err := decoder.ReadUint64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read LamportsPerUint8Year when decoding SysvarRent: %w", err)
	}
	sr.LamportsPerUint8Year = lamportsPerUint8Year

	exemptionThreshold, err := decoder.ReadFloat64(bin.LE)
	if err != nil {
		return fmt.Errorf("failed to read ExemptionThreshold when decoding SysvarRent: %w", err)
	}
	sr.ExemptionThreshold = exemptionThreshold

	burnPercent, err := decoder.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read BurnPercent when decoding SysvarRent: %w", err)
	}
	sr.BurnPercent = burnPercent

	return
}

func (sr *SysvarRent) MustUnmarshalWithDecoder(decoder *bin.Decoder) {
	err := sr.UnmarshalWithDecoder(decoder)
	if err != nil {
		panic(err.Error())
	}
}

func ReadRentSysvar(accts *accounts.Accounts) SysvarRent {
	rentAcct, err := (*accts).GetAccount(&SysvarRentAddr)
	if err != nil {
		panic("failed to read rent sysvar account")
	}

	dec := bin.NewBinDecoder(rentAcct.Data)

	var rent SysvarRent
	rent.MustUnmarshalWithDecoder(dec)

	return rent
}

// TODO: implement logic for writing the rent sysvar and for creating a default
func UpdateRentSysvar(globalCtx *global.GlobalCtx, newRent *SysvarRent) {

}
