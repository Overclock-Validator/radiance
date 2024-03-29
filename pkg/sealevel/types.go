package sealevel

import (
	"encoding/binary"
	"io"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
)

const SolInstructionStructSize = 40

type SolInstruction struct {
	programIdAddr uint64
	accountsAddr  uint64
	accountsLen   uint64
	dataAddr      uint64
	dataLen       uint64
}

type Instruction struct {
	Accounts  []AccountMeta
	Data      []byte
	ProgramId solana.PublicKey
}

const AccountMetaSize = 34

type AccountMeta struct {
	pubkey     solana.PublicKey
	IsSigner   bool
	IsWritable bool
}

type SolAccountMeta struct {
	PubkeyAddr uint64
	IsSigner   byte
	IsWritable byte
}

const SolSignerSeedsCSize = 16

type VectorDescrC struct {
	Addr uint64
	Len  uint64
}

type ConfigKey struct {
	PubKey   solana.PublicKey
	IsSigner bool
}

type InstructionAccount struct {
	IndexInTransaction uint64
	IndexInCaller      uint64
	IndexInCallee      uint64
	IsSigner           bool
	IsWritable         bool
}

func (accountMeta *AccountMeta) Deserialize(buf io.Reader) error {
	err := binary.Read(buf, binary.LittleEndian, &accountMeta.pubkey)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountMeta.IsSigner)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountMeta.IsWritable)
	if err != nil {
		return err
	}
	return nil
}

func (accountMeta *SolAccountMeta) Deserialize(buf io.Reader) error {
	err := binary.Read(buf, binary.LittleEndian, &accountMeta.PubkeyAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountMeta.IsSigner)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountMeta.IsWritable)
	if err != nil {
		return err
	}
	return nil
}

func (solInstr *SolInstruction) Deserialize(buf io.Reader) error {

	err := binary.Read(buf, binary.LittleEndian, &solInstr.programIdAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &solInstr.accountsAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &solInstr.accountsLen)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &solInstr.dataAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &solInstr.dataLen)
	if err != nil {
		return err
	}

	return nil
}

func (vectorDescr *VectorDescrC) Deserialize(buf io.Reader) error {
	err := binary.Read(buf, binary.LittleEndian, &vectorDescr.Addr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &vectorDescr.Len)
	if err != nil {
		return err
	}
	return nil
}

func (configKey *ConfigKey) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	pubKey, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(configKey.PubKey[:], pubKey)

	isSignerByte, err := decoder.ReadByte()
	if err != nil {
		return err
	}

	if isSignerByte == 1 {
		configKey.IsSigner = true
	} else if isSignerByte == 0 {
		configKey.IsSigner = false
	} else {
		return MalformedBool
	}

	return nil
}
