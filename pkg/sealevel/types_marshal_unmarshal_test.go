package sealevel

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarshal_Unmarshal_AccountMeta(t *testing.T) {
	var accountMeta AccountMeta
	accountMeta.Pubkey = SysvarClockAddr
	accountMeta.IsSigner = true
	accountMeta.IsWritable = false

	accountMetaBytes, err := accountMeta.Marshal()
	assert.NoError(t, err)

	var newAccountMeta AccountMeta
	reader := bytes.NewReader(accountMetaBytes)
	err = newAccountMeta.Unmarshal(reader)
	assert.NoError(t, err)

	assert.Equal(t, accountMeta.Pubkey, newAccountMeta.Pubkey)
	assert.Equal(t, accountMeta.IsSigner, newAccountMeta.IsSigner)
	assert.Equal(t, accountMeta.IsWritable, newAccountMeta.IsWritable)
}

func TestMarshal_Unmarshal_SolAccountMeta(t *testing.T) {
	var accountMeta SolAccountMeta
	accountMeta.PubkeyAddr = 22222222
	accountMeta.IsSigner = 1
	accountMeta.IsWritable = 0

	accountMetaBytes, err := accountMeta.Marshal()
	assert.NoError(t, err)

	var newAccountMeta SolAccountMeta
	reader := bytes.NewReader(accountMetaBytes)
	err = newAccountMeta.Unmarshal(reader)
	assert.NoError(t, err)

	assert.Equal(t, accountMeta.PubkeyAddr, newAccountMeta.PubkeyAddr)
	assert.Equal(t, accountMeta.IsSigner, newAccountMeta.IsSigner)
	assert.Equal(t, accountMeta.IsWritable, newAccountMeta.IsWritable)
}

func TestMarshal_Unmarshal_SolInstruction(t *testing.T) {
	var instr SolInstruction
	instr.accountsAddr = 12345
	instr.accountsLen = 1337
	instr.dataAddr = 67890
	instr.dataLen = 1212
	instr.programIdAddr = 11111111

	instrBytes, err := instr.Marshal()
	assert.NoError(t, err)

	var newInstr SolInstruction
	err = newInstr.Unmarshal(bytes.NewReader(instrBytes))
	assert.NoError(t, err)

	assert.Equal(t, instr.accountsAddr, newInstr.accountsAddr)
	assert.Equal(t, instr.accountsLen, newInstr.accountsLen)
	assert.Equal(t, instr.dataAddr, newInstr.dataAddr)
	assert.Equal(t, instr.dataLen, newInstr.dataLen)
	assert.Equal(t, instr.programIdAddr, newInstr.programIdAddr)
}

func TestMarshal_Unmarshal_VectorDescrC(t *testing.T) {
	var descr VectorDescrC
	descr.Addr = 112233
	descr.Len = 1337

	descrBytes, err := descr.Marshal()
	assert.NoError(t, err)

	var newDescr VectorDescrC
	err = newDescr.Unmarshal(bytes.NewReader(descrBytes))
	assert.NoError(t, err)

	assert.Equal(t, descr.Addr, newDescr.Addr)
	assert.Equal(t, descr.Len, newDescr.Len)
}
