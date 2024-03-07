package sealevel

import "github.com/gagliardetto/solana-go"

type InstructionCtx struct {
	programId solana.PublicKey
}

func (instrCtx InstructionCtx) ProgramId() solana.PublicKey {
	return instrCtx.programId
}
