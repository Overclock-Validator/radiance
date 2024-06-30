package sealevel

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/gagliardetto/solana-go"
)

const SolInstructionCStructSize = 40

type SolInstructionC struct {
	ProgramIdAddr uint64
	AccountsAddr  uint64
	AccountsLen   uint64
	DataAddr      uint64
	DataLen       uint64
}

const SolInstructionRustStructSize = 80

type SolInstructionRust struct {
	Accounts VectorDescrRust
	Data     VectorDescrRust
	Pubkey   solana.PublicKey
}

type Instruction struct {
	Accounts  []AccountMeta
	Data      []byte
	ProgramId solana.PublicKey
}

const AccountMetaSize = 34

type AccountMeta struct {
	Pubkey     solana.PublicKey
	IsSigner   bool
	IsWritable bool
}

const SolAccountMetaCSize = 10

type SolAccountMetaC struct {
	PubkeyAddr uint64
	IsSigner   byte
	IsWritable byte
}

const SolAccountMetaRustSize = 34

type SolAccountMetaRust struct {
	Pubkey     solana.PublicKey
	IsSigner   byte
	IsWritable byte
}

const SolSignerSeedsCSize = 16

type VectorDescrC struct {
	Addr uint64
	Len  uint64
}

type VectorDescrRust struct {
	Addr uint64
	Cap  uint64
	Len  uint64
}

type InstructionAccount struct {
	IndexInTransaction uint64
	IndexInCaller      uint64
	IndexInCallee      uint64
	IsSigner           bool
	IsWritable         bool
}

const SolAccountInfoCSize = 51

type SolAccountInfoC struct {
	KeyAddr      uint64
	LamportsAddr uint64
	DataLen      uint64
	DataAddr     uint64
	OwnerAddr    uint64
	RentEpoch    uint64
	IsSigner     bool
	IsWritable   bool
	Executable   bool
}

const SolAccountInfoRustSize = 43

type SolAccountInfoRust struct {
	PubkeyAddr      uint64 // points to uchar[32]
	LamportsBoxAddr uint64 // points to Rc with embedded RefCell which points to u64
	DataBoxAddr     uint64 // points to Rc with embedded RefCell which contains slice which points to bytes
	OwnerAddr       uint64 // points to uchar[32]
	RentEpoch       uint64
	IsSigner        byte
	IsWritable      byte
	Executable      byte
}

const RefCellRustSize = 32

type RefCellRust struct {
	Strong uint64
	Weak   uint64
	Borrow uint64
	Addr   uint64
}

type RefCellVecRust struct {
	Strong uint64
	Weak   uint64
	Borrow uint64
	Addr   uint64
	Len    uint64
}

type TranslatedAccounts []TranslatedAccount

type TranslatedAccount struct {
	IndexOfAccount uint64
	CallerAccount  *CallerAccount
}

type CallerAccount struct {
	Lamports          uint64
	Owner             solana.PublicKey
	SerializedData    *[]byte
	SerializedDataLen uint64
	VmDataAddr        uint64
	RefToLenInVm      uint64
	Executable        bool
	RentEpoch         uint64
}

const ProcessedSiblingInstructionSize = 16

type ProcessedSiblingInstruction struct {
	DataLen     uint64
	AccountsLen uint64
}

func (accountMeta *AccountMeta) Unmarshal(buf io.Reader) error {
	err := binary.Read(buf, binary.LittleEndian, &accountMeta.Pubkey)
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

func (accountMeta *AccountMeta) Marshal() []byte {
	buf := new(bytes.Buffer)

	var err error
	err = binary.Write(buf, binary.LittleEndian, accountMeta.Pubkey)
	if err != nil {
		panic("shouldn't fail")
	}

	err = binary.Write(buf, binary.LittleEndian, accountMeta.IsSigner)
	if err != nil {
		panic("shouldn't fail")
	}

	err = binary.Write(buf, binary.LittleEndian, accountMeta.IsWritable)
	if err != nil {
		panic("shouldn't fail")
	}
	return buf.Bytes()
}

func (accountMeta *SolAccountMetaC) Unmarshal(buf io.Reader) error {
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

func (accountMeta *SolAccountMetaC) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)

	var err error
	err = binary.Write(buf, binary.LittleEndian, accountMeta.PubkeyAddr)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, accountMeta.IsSigner)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, accountMeta.IsWritable)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (accountMeta *SolAccountMetaRust) Unmarshal(buf io.Reader) error {
	err := binary.Read(buf, binary.LittleEndian, &accountMeta.Pubkey)
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

func (solInstr *SolInstructionC) Unmarshal(buf io.Reader) error {
	err := binary.Read(buf, binary.LittleEndian, &solInstr.ProgramIdAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &solInstr.AccountsAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &solInstr.AccountsLen)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &solInstr.DataAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &solInstr.DataLen)
	if err != nil {
		return err
	}

	return nil
}

func (solInstr *SolInstructionC) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.LittleEndian, solInstr.ProgramIdAddr)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, solInstr.AccountsAddr)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, solInstr.AccountsLen)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, solInstr.DataAddr)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, solInstr.DataLen)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (solInstr *SolInstructionRust) Unmarshal(buf io.Reader) error {
	err := solInstr.Accounts.Unmarshal(buf)
	if err != nil {
		return err
	}

	err = solInstr.Data.Unmarshal(buf)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &solInstr.Pubkey)
	if err != nil {
		return err
	}

	return nil
}

func (solInstr *SolInstructionRust) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)

	accountsBytes, err := solInstr.Accounts.Marshal()
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, accountsBytes)

	dataBytes, err := solInstr.Data.Marshal()
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, dataBytes)

	err = binary.Write(buf, binary.LittleEndian, solInstr.Pubkey)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (vectorDescr *VectorDescrC) Unmarshal(buf io.Reader) error {
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

func (vectorDescr *VectorDescrC) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.LittleEndian, vectorDescr.Addr)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, vectorDescr.Len)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (vectorDescr *VectorDescrRust) Unmarshal(buf io.Reader) error {
	err := binary.Read(buf, binary.LittleEndian, &vectorDescr.Addr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &vectorDescr.Cap)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &vectorDescr.Len)
	if err != nil {
		return err
	}
	return nil
}

func (vectorDescr *VectorDescrRust) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.LittleEndian, vectorDescr.Addr)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, vectorDescr.Cap)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.LittleEndian, vectorDescr.Len)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (accountInfo *SolAccountInfoC) Unmarshal(buf io.Reader) error {
	err := binary.Read(buf, binary.LittleEndian, &accountInfo.KeyAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.LamportsAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.DataLen)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.DataAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.OwnerAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.RentEpoch)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.IsSigner)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.IsWritable)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.Executable)
	if err != nil {
		return err
	}

	return nil
}

func (accountInfo *SolAccountInfoRust) Unmarshal(buf io.Reader) error {
	err := binary.Read(buf, binary.LittleEndian, &accountInfo.PubkeyAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.LamportsBoxAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.DataBoxAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.OwnerAddr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.RentEpoch)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.IsSigner)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.IsWritable)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &accountInfo.Executable)
	if err != nil {
		return err
	}

	return nil
}

func (refCell *RefCellRust) Unmarshal(buf io.Reader) error {
	err := binary.Read(buf, binary.LittleEndian, &refCell.Strong)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &refCell.Weak)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &refCell.Borrow)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &refCell.Addr)
	if err != nil {
		return err
	}

	return nil
}

func (refCellVec *RefCellVecRust) Unmarshal(buf io.Reader) error {
	err := binary.Read(buf, binary.LittleEndian, &refCellVec.Strong)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &refCellVec.Weak)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &refCellVec.Borrow)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &refCellVec.Addr)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &refCellVec.Len)
	if err != nil {
		return err
	}

	return nil
}

func (psi *ProcessedSiblingInstruction) Unmarshal(buf io.Reader) error {
	err := binary.Read(buf, binary.LittleEndian, &psi.DataLen)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &psi.AccountsLen)
	if err != nil {
		return err
	}
	return nil
}

func (psi *ProcessedSiblingInstruction) Marshal() []byte {
	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.LittleEndian, psi.DataLen)
	if err != nil {
		panic("shouldn't fail")
	}

	err = binary.Write(buf, binary.LittleEndian, psi.AccountsLen)
	if err != nil {
		panic("shouldn't fail")
	}

	return buf.Bytes()
}
