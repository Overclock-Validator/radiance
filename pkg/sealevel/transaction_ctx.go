package sealevel

import "github.com/gagliardetto/solana-go"

type TxReturnData struct {
	programId solana.PublicKey
	data      []byte
}

type TransactionCtx struct {
	instructionStack []InstructionCtx
	returnData       TxReturnData
}

func (txCtx TransactionCtx) PushInstructionCtx(ixCtx InstructionCtx) {
	txCtx.instructionStack = append(txCtx.instructionStack, ixCtx)
}

func (txCtx TransactionCtx) InstructionCtxStackHeight() uint64 {
	return uint64(len(txCtx.instructionStack))
}

func (txCtx TransactionCtx) CurrentInstructionCtx() InstructionCtx {
	level := txCtx.InstructionCtxStackHeight() - 1
	return txCtx.instructionStack[level]
}

func (txCtx TransactionCtx) GetReturnData() (solana.PublicKey, []byte) {
	return txCtx.returnData.programId, txCtx.returnData.data
}

func (txCtx TransactionCtx) SetReturnData(programId solana.PublicKey, data []byte) {
	txCtx.returnData.programId = programId
	txCtx.returnData.data = data
}
