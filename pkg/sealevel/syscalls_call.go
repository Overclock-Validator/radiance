package sealevel

import (
	"bytes"
	"unsafe"

	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/safemath"
	"go.firedancer.io/radiance/pkg/sbpf"
)

// SyscallGetStackHeightImpl is an implementation of the sol_get_stack_height syscall
func SyscallGetStackHeightImpl(vm sbpf.VM) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = execCtx.ComputeMeter.Consume(CUSyscallBaseCost)
	if err != nil {
		return
	}

	r0 = transactionCtx(vm).InstructionCtxStackHeight()
	return
}

var SyscallGetStackHeight = sbpf.SyscallFunc0(SyscallGetStackHeightImpl)

// SyscallGetReturnDataImpl is an implementation of the sol_get_return_data syscall
func SyscallGetReturnDataImpl(vm sbpf.VM, returnDataAddr, length, programIdAddr uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	err = execCtx.ComputeMeter.Consume(CUSyscallBaseCost)
	if err != nil {
		return
	}

	programId, returnData := transactionCtx(vm).ReturnData()

	if length > uint64(len(returnData)) {
		length = uint64(len(returnData))
	}

	if length != 0 {
		result := safemath.SaturatingAddU64(length, solana.PublicKeyLength) / CUCpiBytesPerUnit
		err = execCtx.ComputeMeter.Consume(result)
		if err != nil {
			return
		}

		var returnDataResult []byte
		returnDataResult, err = vm.Translate(returnDataAddr, length, true)
		if err != nil {
			return
		}

		if len(returnData) != len(returnDataResult) {
			err = SyscallErrInvalidLength
			return
		}

		copy(returnDataResult, returnData)

		var programIdResult []byte
		programIdResult, err = vm.Translate(programIdAddr, solana.PublicKeyLength, true)
		if err != nil {
			return
		}

		if !isNonOverlapping(returnDataAddr, length, programIdAddr, solana.PublicKeyLength) {
			err = SyscallErrCopyOverlapping
			return
		}

		copy(programIdResult, programId[:])
	}

	r0 = uint64(len(returnData))
	return
}

var SyscallGetReturnData = sbpf.SyscallFunc3(SyscallGetReturnDataImpl)

const MaxReturnData = 1024

// SyscallSetReturnDataImpl is an implementation of the sol_set_return_data syscall
func SyscallSetReturnDataImpl(vm sbpf.VM, addr, length uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	cost := safemath.SaturatingAddU64(length/CUCpiBytesPerUnit, CUSyscallBaseCost)
	err = execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return
	}

	if length > MaxReturnData {
		err = SyscallErrReturnDataTooLarge
		return
	}

	var returnData []byte
	if length == 0 {
		returnData = make([]byte, 0)
	} else {
		returnData, err = vm.Translate(addr, length, false)
		if err != nil {
			return
		}
	}

	txCtx := transactionCtx(vm)
	ixCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return
	}
	programId := ixCtx.ProgramId()

	txCtx.SetReturnData(programId, returnData)

	r0 = 0
	return
}

var SyscallSetReturnData = sbpf.SyscallFunc2(SyscallSetReturnDataImpl)

func castToPtr(obj any) uint64 {
	return uint64(uintptr(unsafe.Pointer(&obj)))
}

// SyscallGetProcessedSiblingInstructionImpl is an implementation of the sol_get_processed_sibling_instruction syscall
func SyscallGetProcessedSiblingInstructionImpl(vm sbpf.VM, index, metaAddr, programIdAddr, dataAddr, accountsAddr uint64) (r0 uint64, err error) {
	execCtx := executionCtx(vm)
	txCtx := transactionCtx(vm)

	err = execCtx.ComputeMeter.Consume(CUSyscallBaseCost)
	if err != nil {
		return
	}

	stackHeight := execCtx.StackHeight()
	instrTraceLen := txCtx.InstructionTraceLength()

	var reverseIndexAtStackHeight uint64
	var instrCtxFound *InstructionCtx

	for indexInTrace := instrTraceLen; indexInTrace > 0; indexInTrace-- {
		instrCtx, err := txCtx.InstructionCtxAtIndexInTrace(indexInTrace)
		if err != nil {
			return r0, err
		}
		if instrCtx.StackHeight() < stackHeight {
			break
		}
		if instrCtx.StackHeight() == stackHeight {
			if safemath.SaturatingAddU64(index, 1) == reverseIndexAtStackHeight {
				instrCtxFound = instrCtx
				break
			}
			reverseIndexAtStackHeight = safemath.SaturatingAddU64(reverseIndexAtStackHeight, 1)
		}
	}

	if instrCtxFound != nil {
		resultsHeaderBytes, err := vm.Translate(metaAddr, ProcessedSiblingInstructionSize, false)
		if err != nil {
			return r0, err
		}

		reader := bytes.NewReader(resultsHeaderBytes)

		var resultHeader ProcessedSiblingInstruction
		err = resultHeader.Unmarshal(reader)
		if err != nil {
			return r0, err
		}

		if resultHeader.DataLen == uint64(len(instrCtxFound.Data)) &&
			resultHeader.AccountsLen == instrCtxFound.NumberOfInstructionAccounts() {

			programIdBytes, err := vm.Translate(programIdAddr, solana.PublicKeyLength, true)
			if err != nil {
				return r0, err
			}
			programId := solana.PublicKeyFromBytes(programIdBytes)

			data, err := vm.Translate(dataAddr, resultHeader.DataLen, true)
			if err != nil {
				return r0, err
			}

			accountMetaDataSize := safemath.SaturatingMulU64(resultHeader.AccountsLen, AccountMetaSize)
			accountMetaSliceBytes, err := vm.Translate(accountsAddr, accountMetaDataSize, true)
			if err != nil {
				return r0, err
			}

			reader.Reset(accountMetaSliceBytes)

			var accounts []AccountMeta
			for i := uint64(0); i < resultHeader.AccountsLen; i++ {
				var account AccountMeta
				err = account.Unmarshal(reader)
				if err != nil {
					return r0, err
				}
				accounts = append(accounts, account)
			}

			if !isNonOverlapping(castToPtr(resultHeader), ProcessedSiblingInstructionSize, castToPtr(programId), solana.PublicKeyLength) ||
				!isNonOverlapping(castToPtr(resultHeader), ProcessedSiblingInstructionSize, castToPtr(accounts), accountMetaDataSize) ||
				!isNonOverlapping(castToPtr(resultHeader), ProcessedSiblingInstructionSize, castToPtr(data), resultHeader.DataLen) ||
				!isNonOverlapping(castToPtr(programId), solana.PublicKeyLength, castToPtr(data), resultHeader.DataLen) ||
				!isNonOverlapping(castToPtr(programId), solana.PublicKeyLength, castToPtr(accounts), accountMetaDataSize) ||
				!isNonOverlapping(castToPtr(data), resultHeader.DataLen, castToPtr(accounts), accountMetaDataSize) {
				return r0, SyscallErrCopyOverlapping
			}

			pk, err := instrCtxFound.LastProgramKey(transactionCtx(vm))
			if err != nil {
				return r0, err
			}

			// copy out programID pubkey
			copy(programIdBytes, pk[:])

			// copy out instruction data
			copy(data, instrCtxFound.Data)

			// build AccountMetas, serialize them and then copy them out
			writer := bytes.NewBuffer(accountMetaSliceBytes)

			for instrAcctIdx := uint64(0); instrAcctIdx < instrCtxFound.NumberOfInstructionAccounts(); instrAcctIdx++ {
				idx, err := instrCtxFound.IndexOfInstructionAccountInTransaction(instrAcctIdx)
				if err != nil {
					return r0, err
				}
				key, err := txCtx.KeyOfAccountAtIndex(idx)
				if err != nil {
					return r0, err
				}

				isSigner, err := instrCtxFound.IsInstructionAccountSigner(instrAcctIdx)
				if err != nil {
					return r0, err
				}

				isWritable, err := instrCtxFound.IsInstructionAccountWritable(instrAcctIdx)
				if err != nil {
					return r0, err
				}

				acctMeta := AccountMeta{Pubkey: key, IsSigner: isSigner, IsWritable: isWritable}
				acctBytes := acctMeta.Marshal()
				writer.Write(acctBytes)
			}
		}

		// build a new result header, serialize it & copy it out
		var resultHeaderOut ProcessedSiblingInstruction
		resultHeaderOut.DataLen = uint64(len(instrCtxFound.Data))
		resultHeaderOut.AccountsLen = instrCtxFound.NumberOfInstructionAccounts()
		resultHeaderOutBytes := resultHeaderOut.Marshal()

		copy(resultsHeaderBytes, resultHeaderOutBytes)

		r0 = 1
		return r0, nil
	}

	r0 = 0
	return
}

var SyscallGetProcessedSiblingInstruction = sbpf.SyscallFunc5(SyscallGetProcessedSiblingInstructionImpl)
