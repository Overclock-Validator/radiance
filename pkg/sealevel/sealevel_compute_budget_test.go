package sealevel

import (
	"bytes"
	"math"
	"testing"

	"github.com/Overclock-Validator/mithril/pkg/accounts"
	"github.com/Overclock-Validator/mithril/pkg/cu"
	bin "github.com/gagliardetto/binary"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

// ComputeBudget program tests

func TestExecute_Tx_ComputeBudget_Program_Entry_Point(t *testing.T) {

	programAcctData := make([]byte, 500, 500)
	programAcct := accounts.Account{Key: ComputeBudgetProgramAddr, Lamports: 0, Data: programAcctData, Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}
	transactionAccts := NewTransactionAccounts([]accounts.Account{programAcct})

	instructionAccts := []InstructionAccount{
		{IndexInTransaction: 0, IndexInCaller: 0, IndexInCallee: 0, IsSigner: true, IsWritable: true},
	}

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)

	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeterDefault()}
	err := execCtx.ProcessInstruction([]byte{}, instructionAccts, []uint64{0})
	require.NoError(t, err)
}

func newTestSetComputeUnitLimit(units uint32) (Instruction, error) {
	var setComputeUnitLimit ComputeBudgetInstrSetComputeUnitLimit
	setComputeUnitLimit.ComputeUnitLimit = units

	writer := new(bytes.Buffer)
	encoder := bin.NewBorshEncoder(writer)
	err := setComputeUnitLimit.MarshalWithEncoder(encoder)
	if err != nil {
		return Instruction{}, err
	}

	instr := Instruction{ProgramId: ComputeBudgetProgramAddr, Data: writer.Bytes()}
	return instr, nil
}

func newTestSetComputeUnitPrice(microLamports uint64) (Instruction, error) {
	var setComputeUnitPrice ComputeBudgetInstrSetComputeUnitPrice
	setComputeUnitPrice.MicroLamports = microLamports
	writer := new(bytes.Buffer)
	encoder := bin.NewBorshEncoder(writer)
	err := setComputeUnitPrice.MarshalWithEncoder(encoder)
	if err != nil {
		return Instruction{}, err
	}

	instr := Instruction{ProgramId: ComputeBudgetProgramAddr, Data: writer.Bytes()}
	return instr, nil
}

func newTestRequestHeapFrame(numBytes uint32) (Instruction, error) {
	var requestHeapFrame ComputeBudgetInstrRequestHeapFrame
	requestHeapFrame.Bytes = numBytes
	writer := new(bytes.Buffer)
	encoder := bin.NewBorshEncoder(writer)
	err := requestHeapFrame.MarshalWithEncoder(encoder)
	if err != nil {
		return Instruction{}, err
	}

	instr := Instruction{ProgramId: ComputeBudgetProgramAddr, Data: writer.Bytes()}
	return instr, nil
}

func newTestComputeBudgetInstrSetLoadedAccountsDataSizeLimit(numBytes uint32) (Instruction, error) {
	var setLoadedAccountsDataSizeLimit ComputeBudgetInstrSetLoadedAccountsDataSizeLimit
	setLoadedAccountsDataSizeLimit.Bytes = numBytes
	writer := new(bytes.Buffer)
	encoder := bin.NewBorshEncoder(writer)
	err := setLoadedAccountsDataSizeLimit.MarshalWithEncoder(encoder)
	if err != nil {
		return Instruction{}, err
	}

	instr := Instruction{ProgramId: ComputeBudgetProgramAddr, Data: writer.Bytes()}
	return instr, nil
}

func TestExecute_Tx_ComputeBudget_Instructions(t *testing.T) {

	// 1
	cbl, err := ComputeBudgetExecuteInstructions([]Instruction{})
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), cbl.ComputeUnitLimit)
	assert.Equal(t, uint32(MinHeapFrameBytes), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint64(0), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(MaxLoadedAccountsDataSizeBytes), cbl.LoadedAccountBytes)

	// 2
	instr, err := newTestSetComputeUnitLimit(1)
	assert.NoError(t, err)
	blankInstr := Instruction{Data: []byte{0}}
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{instr, blankInstr})
	assert.NoError(t, err)
	assert.Equal(t, uint32(1), cbl.ComputeUnitLimit)
	assert.Equal(t, uint32(MinHeapFrameBytes), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint64(0), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(MaxLoadedAccountsDataSizeBytes), cbl.LoadedAccountBytes)

	// 3
	instr, err = newTestSetComputeUnitLimit(MaxComputeUnitLimit + 1)
	assert.NoError(t, err)
	blankInstr = Instruction{Data: []byte{0}}
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{instr, blankInstr})
	assert.NoError(t, err)
	assert.Equal(t, uint32(MaxComputeUnitLimit), cbl.ComputeUnitLimit)
	assert.Equal(t, uint32(MinHeapFrameBytes), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint64(0), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(MaxLoadedAccountsDataSizeBytes), cbl.LoadedAccountBytes)

	// 4
	instr, err = newTestSetComputeUnitLimit(MaxComputeUnitLimit)
	assert.NoError(t, err)
	blankInstr = Instruction{Data: []byte{0}}
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{blankInstr, instr})
	assert.NoError(t, err)
	assert.Equal(t, uint32(MaxComputeUnitLimit), cbl.ComputeUnitLimit)
	assert.Equal(t, uint32(MinHeapFrameBytes), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint64(0), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(MaxLoadedAccountsDataSizeBytes), cbl.LoadedAccountBytes)

	// 5
	instr, err = newTestSetComputeUnitLimit(1)
	assert.NoError(t, err)
	blankInstr = Instruction{Data: []byte{0}}
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{blankInstr, blankInstr, blankInstr, instr})
	assert.NoError(t, err)
	assert.Equal(t, uint32(1), cbl.ComputeUnitLimit)
	assert.Equal(t, uint32(MinHeapFrameBytes), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint64(0), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(MaxLoadedAccountsDataSizeBytes), cbl.LoadedAccountBytes)

	// 6
	instr1, err := newTestSetComputeUnitLimit(1)
	assert.NoError(t, err)
	instr2, err := newTestSetComputeUnitPrice(42)
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{instr1, instr2})
	assert.NoError(t, err)
	assert.Equal(t, uint32(1), cbl.ComputeUnitLimit)
	assert.Equal(t, uint64(42), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(MinHeapFrameBytes), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint32(MaxLoadedAccountsDataSizeBytes), cbl.LoadedAccountBytes)

	// 7
	instr1, err = newTestRequestHeapFrame(40 * 1024)
	assert.NoError(t, err)
	blankInstr = Instruction{Data: []byte{0}}
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{instr1, blankInstr})
	assert.NoError(t, err)
	assert.Equal(t, uint32(DefaultInstructionComputeUnitLimit), cbl.ComputeUnitLimit)
	assert.Equal(t, uint64(0), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(40*1024), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint32(MaxLoadedAccountsDataSizeBytes), cbl.LoadedAccountBytes)

	// 8
	instr1, err = newTestRequestHeapFrame((40 * 1024) + 1)
	assert.NoError(t, err)
	blankInstr = Instruction{Data: []byte{0}}
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{instr1, blankInstr})
	assert.Equal(t, invalidInstructionDataErr(0), err)

	// 9
	instr1, err = newTestRequestHeapFrame(31 * 1024)
	assert.NoError(t, err)
	blankInstr = Instruction{Data: []byte{0}}
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{instr1, blankInstr})
	assert.Equal(t, invalidInstructionDataErr(0), err)

	// 10
	instr1, err = newTestRequestHeapFrame(MaxHeapFrameBytes + 1)
	assert.NoError(t, err)
	blankInstr = Instruction{Data: []byte{0}}
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{instr1, blankInstr})
	assert.Equal(t, invalidInstructionDataErr(0), err)

	// 11
	instr1, err = newTestRequestHeapFrame(MaxHeapFrameBytes)
	assert.NoError(t, err)
	blankInstr = Instruction{Data: []byte{0}}
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{blankInstr, instr1})
	assert.NoError(t, err)
	assert.Equal(t, uint32(DefaultInstructionComputeUnitLimit), cbl.ComputeUnitLimit)
	assert.Equal(t, uint32(MaxHeapFrameBytes), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint64(0), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(MaxLoadedAccountsDataSizeBytes), cbl.LoadedAccountBytes)

	// 12
	instr1, err = newTestRequestHeapFrame(1)
	assert.NoError(t, err)
	blankInstr = Instruction{Data: []byte{0}}
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{blankInstr, blankInstr, blankInstr, instr1})
	assert.Equal(t, invalidInstructionDataErr(3), err)

	// 13
	blankInstr = Instruction{Data: []byte{0}}
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{blankInstr, blankInstr, blankInstr, blankInstr, blankInstr, blankInstr, blankInstr})
	assert.NoError(t, err)
	assert.Equal(t, uint32(DefaultInstructionComputeUnitLimit*7), cbl.ComputeUnitLimit)
	assert.Equal(t, uint32(MinHeapFrameBytes), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint64(0), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(MaxLoadedAccountsDataSizeBytes), cbl.LoadedAccountBytes)

	// 14
	blankInstr = Instruction{Data: []byte{0}}
	rhf, err := newTestRequestHeapFrame(MaxHeapFrameBytes)
	assert.NoError(t, err)
	scul, err := newTestSetComputeUnitLimit(MaxComputeUnitLimit)
	assert.NoError(t, err)
	scup, err := newTestSetComputeUnitPrice(math.MaxUint64)
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{blankInstr, rhf, scul, scup})
	assert.NoError(t, err)
	assert.Equal(t, uint64(math.MaxUint64), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(MaxComputeUnitLimit), cbl.ComputeUnitLimit)
	assert.Equal(t, uint32(MaxHeapFrameBytes), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint32(MaxLoadedAccountsDataSizeBytes), cbl.LoadedAccountBytes)

	// 15
	blankInstr = Instruction{Data: []byte{0}}
	scul, err = newTestSetComputeUnitLimit(1)
	assert.NoError(t, err)
	rhf, err = newTestRequestHeapFrame(MaxHeapFrameBytes)
	assert.NoError(t, err)
	scup, err = newTestSetComputeUnitPrice(math.MaxUint64)
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{blankInstr, scul, rhf, scup})
	assert.NoError(t, err)
	assert.Equal(t, uint64(math.MaxUint64), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(1), cbl.ComputeUnitLimit)
	assert.Equal(t, uint32(MaxHeapFrameBytes), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint32(MaxLoadedAccountsDataSizeBytes), cbl.LoadedAccountBytes)

	// 16
	blankInstr = Instruction{Data: []byte{0}}
	scul, err = newTestSetComputeUnitLimit(MaxComputeUnitLimit)
	assert.NoError(t, err)
	scul2, err := newTestSetComputeUnitLimit(MaxComputeUnitLimit - 1)
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{blankInstr, scul, scul2})
	assert.Equal(t, duplicateInstructionErr(2), err)

	// 17
	blankInstr = Instruction{Data: []byte{0}}
	rhf1, err := newTestRequestHeapFrame(MinHeapFrameBytes)
	assert.NoError(t, err)
	rhf2, err := newTestRequestHeapFrame(MaxHeapFrameBytes)
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{blankInstr, rhf1, rhf2})
	assert.Equal(t, duplicateInstructionErr(2), err)

	// 18
	blankInstr = Instruction{Data: []byte{0}}
	scup, err = newTestSetComputeUnitPrice(0)
	assert.NoError(t, err)
	scup2, err := newTestSetComputeUnitPrice(math.MaxUint64)
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{blankInstr, scup, scup2})
	assert.Equal(t, duplicateInstructionErr(2), err)

	// 19
	instr1, err = newTestComputeBudgetInstrSetLoadedAccountsDataSizeLimit(1234)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{instr1})
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), cbl.ComputeUnitLimit)
	assert.Equal(t, uint32(MinHeapFrameBytes), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint64(0), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(1234), cbl.LoadedAccountBytes)

	// 20
	instr1, err = newTestComputeBudgetInstrSetLoadedAccountsDataSizeLimit(MaxLoadedAccountsDataSizeBytes + 1)
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{instr1})
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), cbl.ComputeUnitLimit)
	assert.Equal(t, uint32(MinHeapFrameBytes), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint64(0), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(MaxLoadedAccountsDataSizeBytes), cbl.LoadedAccountBytes)

	// 21
	instr1, err = newTestComputeBudgetInstrSetLoadedAccountsDataSizeLimit(MaxLoadedAccountsDataSizeBytes + 1)
	assert.NoError(t, err)
	instr2, err = newTestSetComputeUnitLimit(1234)
	assert.NoError(t, err)
	cbl, err = ComputeBudgetExecuteInstructions([]Instruction{blankInstr, blankInstr, blankInstr, instr1, instr2})
	assert.NoError(t, err)
	assert.Equal(t, uint32(1234), cbl.ComputeUnitLimit)
	assert.Equal(t, uint32(MinHeapFrameBytes), cbl.UpdatedHeapBytes)
	assert.Equal(t, uint64(0), cbl.ComputeUnitPrice)
	assert.Equal(t, uint32(MaxLoadedAccountsDataSizeBytes), cbl.LoadedAccountBytes)
}
