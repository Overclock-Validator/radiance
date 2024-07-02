package sealevel

import (
	"bytes"
	"testing"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestMarshal_Unmarshal_AccountMeta(t *testing.T) {
	var accountMeta AccountMeta
	accountMeta.Pubkey = SysvarClockAddr
	accountMeta.IsSigner = true
	accountMeta.IsWritable = false

	accountMetaBytes := accountMeta.Marshal()

	var newAccountMeta AccountMeta
	reader := bytes.NewReader(accountMetaBytes)
	err := newAccountMeta.Unmarshal(reader)
	assert.NoError(t, err)

	assert.Equal(t, accountMeta.Pubkey, newAccountMeta.Pubkey)
	assert.Equal(t, accountMeta.IsSigner, newAccountMeta.IsSigner)
	assert.Equal(t, accountMeta.IsWritable, newAccountMeta.IsWritable)
}

func TestMarshal_Unmarshal_SolAccountMeta(t *testing.T) {
	var accountMeta SolAccountMetaC
	accountMeta.PubkeyAddr = 22222222
	accountMeta.IsSigner = 1
	accountMeta.IsWritable = 0

	accountMetaBytes, err := accountMeta.Marshal()
	assert.NoError(t, err)

	var newAccountMeta SolAccountMetaC
	reader := bytes.NewReader(accountMetaBytes)
	err = newAccountMeta.Unmarshal(reader)
	assert.NoError(t, err)

	assert.Equal(t, accountMeta.PubkeyAddr, newAccountMeta.PubkeyAddr)
	assert.Equal(t, accountMeta.IsSigner, newAccountMeta.IsSigner)
	assert.Equal(t, accountMeta.IsWritable, newAccountMeta.IsWritable)
}

type Suite struct {
	suite.Suite
}

func TestMarshal_Unmarshal_SolInstruction(t *testing.T) {
	var instr SolInstructionC
	instr.AccountsAddr = 12345
	instr.AccountsLen = 1337
	instr.DataAddr = 67890
	instr.DataLen = 1212
	instr.ProgramIdAddr = 11111111

	instrBytes, err := instr.Marshal()
	assert.NoError(t, err)

	var newInstr SolInstructionC
	err = newInstr.Unmarshal(bytes.NewReader(instrBytes))
	assert.NoError(t, err)

	assert.Equal(t, instr.AccountsAddr, newInstr.AccountsAddr)
	assert.Equal(t, instr.AccountsLen, newInstr.AccountsLen)
	assert.Equal(t, instr.DataAddr, newInstr.DataAddr)
	assert.Equal(t, instr.DataLen, newInstr.DataLen)
	assert.Equal(t, instr.ProgramIdAddr, newInstr.ProgramIdAddr)
}

func Benchmark_Marshal_Unmarshal_SolInstruction(t *testing.B) {

	s := new(Suite)
	s.SetT(&testing.T{})
	t.ResetTimer()

	var instr SolInstructionC
	instr.AccountsAddr = 12345
	instr.AccountsLen = 1337
	instr.DataAddr = 67890
	instr.DataLen = 1212
	instr.ProgramIdAddr = 11111111

	instrBytes, err := instr.Marshal()
	assert.NoError(t, err)

	var newInstr SolInstructionC

	t.StartTimer()

	for i := 0; i < 10000000; i++ {
		err = newInstr.Unmarshal(bytes.NewReader(instrBytes))
		assert.NoError(t, err)
	}

	t.StopTimer()

	assert.NoError(t, err)

	assert.Equal(t, instr.AccountsAddr, newInstr.AccountsAddr)
	assert.Equal(t, instr.AccountsLen, newInstr.AccountsLen)
	assert.Equal(t, instr.DataAddr, newInstr.DataAddr)
	assert.Equal(t, instr.DataLen, newInstr.DataLen)
	assert.Equal(t, instr.ProgramIdAddr, newInstr.ProgramIdAddr)
}

func ParseBincode[T any](data []byte) (*T, error) {
	dec := bin.NewBinDecoder(data)
	val := new(T)
	err := dec.Decode(val)
	return val, err
}

func Benchmark_Marshal_Unmarshal_SolInstruction_Reflection(t *testing.B) {

	s := new(Suite)
	s.SetT(&testing.T{})
	t.ResetTimer()

	var instr SolInstructionC
	instr.AccountsAddr = 12345
	instr.AccountsLen = 1337
	instr.DataAddr = 67890
	instr.DataLen = 1212
	instr.ProgramIdAddr = 11111111

	instrBytes, err := instr.Marshal()
	assert.NoError(t, err)

	var newInstr *SolInstructionC
	t.StartTimer()

	for i := 0; i < 10000000; i++ {
		newInstr, err = ParseBincode[SolInstructionC](instrBytes)
		assert.NoError(t, err)
	}

	t.StopTimer()

	assert.NoError(t, err)

	assert.Equal(t, instr.AccountsAddr, newInstr.AccountsAddr)
	assert.Equal(t, instr.AccountsLen, newInstr.AccountsLen)
	assert.Equal(t, instr.DataAddr, newInstr.DataAddr)
	assert.Equal(t, instr.DataLen, newInstr.DataLen)
	assert.Equal(t, instr.ProgramIdAddr, newInstr.ProgramIdAddr)
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

func TestMarshal_Unmarshal_ConfigKeys(t *testing.T) {
	var configKeys []ConfigKey

	for i := 0; i < 5; i++ {
		var ck ConfigKey
		privKey, err := solana.NewRandomPrivateKey()
		assert.NoError(t, err)
		ck.Pubkey = privKey.PublicKey()
		ck.IsSigner = true
		configKeys = append(configKeys, ck)
	}

	ckBytes := marshalConfigKeys(configKeys)

	configKeysRecovered, err := unmarshalConfigKeys(ckBytes, true)
	assert.NoError(t, err)

	for i := 0; i < 5; i++ {
		assert.Equal(t, configKeys[i].Pubkey, configKeysRecovered[i].Pubkey)
		assert.Equal(t, configKeys[i].IsSigner, configKeysRecovered[i].IsSigner)
	}
}
