package sealevel

import (
	"bytes"
	"fmt"

	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
)

const SysvarRentAddrStr = "SysvarRent111111111111111111111111111111111"

var SysvarRentAddr = base58.MustDecodeFromString(SysvarRentAddrStr)

const SysvarRentStructLen = 17

const rentAccountStorageOverhead = 128

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

func (sr *SysvarRent) MinimumBalance(dataLen uint64) uint64 {
	min := float64((rentAccountStorageOverhead+dataLen)*sr.LamportsPerUint8Year) * sr.ExemptionThreshold
	return uint64(min)
}

func (sr *SysvarRent) IsExempt(balance uint64, dataLen uint64) bool {
	return balance >= sr.MinimumBalance(dataLen)
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

func WriteRentSysvar(accts *accounts.Accounts, rent SysvarRent) {

	rentSysvarAcct, err := (*accts).GetAccount(&SysvarRentAddr)
	if err != nil {
		panic("failed to read Rent sysvar account")
	}

	data := new(bytes.Buffer)
	enc := bin.NewBinEncoder(data)

	err = enc.WriteUint64(rent.LamportsPerUint8Year, bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize LamportsPerUint8Year for Rent sysvar: %w", err)
		panic(err)
	}

	err = enc.WriteFloat64(rent.ExemptionThreshold, bin.LE)
	if err != nil {
		err = fmt.Errorf("failed to serialize ExemptionThreshold for Rent sysvar: %w", err)
		panic(err)
	}

	err = enc.WriteByte(rent.BurnPercent)
	if err != nil {
		err = fmt.Errorf("failed to serialize BurnPercent for Rent sysvar: %w", err)
		panic(err)
	}

	copy(rentSysvarAcct.Data, data.Bytes())

	err = (*accts).SetAccount(&SysvarRentAddr, rentSysvarAcct)
	if err != nil {
		err = fmt.Errorf("failed write newly serialized Rent sysvar to sysvar account: %w", err)
		panic(err)
	}
}

func checkAcctForRentSysvar(txCtx *TransactionCtx, instrCtx *InstructionCtx, instrAcctIdx uint64) error {
	idxInTx, err := instrCtx.IndexOfInstructionAccountInTransaction(instrAcctIdx)
	if err != nil {
		return err
	}
	pk, err := txCtx.KeyOfAccountAtIndex(idxInTx)
	if err != nil {
		return err
	}
	if pk == SysvarRentAddr {
		return nil
	} else {
		return InstrErrInvalidArgument
	}
}
