package sealevel

import (
	"bytes"
	"unsafe"

	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/safemath"
	"go.firedancer.io/radiance/pkg/sbpf"
)

// SyscallGetStackHeightImpl is an implementation of the sol_get_stack_height syscall
func SyscallGetStackHeightImpl(vm sbpf.VM) (uint64, error) {
	execCtx := executionCtx(vm)
	err := execCtx.ComputeMeter.Consume(CUSyscallBaseCost)
	if err != nil {
		return syscallCuErr()
	}

	return syscallSuccess(transactionCtx(vm).InstructionCtxStackHeight())
}

var SyscallGetStackHeight = sbpf.SyscallFunc0(SyscallGetStackHeightImpl)

// SyscallGetReturnDataImpl is an implementation of the sol_get_return_data syscall
func SyscallGetReturnDataImpl(vm sbpf.VM, returnDataAddr, length, programIdAddr uint64) (uint64, error) {
	execCtx := executionCtx(vm)
	err := execCtx.ComputeMeter.Consume(CUSyscallBaseCost)
	if err != nil {
		return syscallCuErr()
	}

	programId, returnData := transactionCtx(vm).ReturnData()

	if length > uint64(len(returnData)) {
		length = uint64(len(returnData))
	}

	if length != 0 {
		result := safemath.SaturatingAddU64(length, solana.PublicKeyLength) / CUCpiBytesPerUnit
		err = execCtx.ComputeMeter.Consume(result)
		if err != nil {
			return syscallCuErr()
		}

		var returnDataResult []byte
		returnDataResult, err = vm.Translate(returnDataAddr, length, true)
		if err != nil {
			return syscallErr(err)
		}

		if len(returnData) != len(returnDataResult) {
			syscallErr(SyscallErrInvalidLength)
		}

		copy(returnDataResult, returnData)

		var programIdResult []byte
		programIdResult, err = vm.Translate(programIdAddr, solana.PublicKeyLength, true)
		if err != nil {
			return syscallErr(err)
		}

		if !isNonOverlapping(returnDataAddr, length, programIdAddr, solana.PublicKeyLength) {
			return syscallErr(SyscallErrCopyOverlapping)
		}

		copy(programIdResult, programId[:])
	}

	return syscallSuccess(uint64(len(returnData)))
}

var SyscallGetReturnData = sbpf.SyscallFunc3(SyscallGetReturnDataImpl)

const MaxReturnData = 1024

// SyscallSetReturnDataImpl is an implementation of the sol_set_return_data syscall
func SyscallSetReturnDataImpl(vm sbpf.VM, addr, length uint64) (uint64, error) {
	execCtx := executionCtx(vm)
	cost := safemath.SaturatingAddU64(length/CUCpiBytesPerUnit, CUSyscallBaseCost)
	err := execCtx.ComputeMeter.Consume(cost)
	if err != nil {
		return syscallCuErr()
	}

	if length > MaxReturnData {
		return syscallErr(SyscallErrReturnDataTooLarge)
	}

	var returnData []byte
	if length == 0 {
		returnData = make([]byte, 0)
	} else {
		returnData, err = vm.Translate(addr, length, false)
		if err != nil {
			return syscallErr(err)
		}
	}

	txCtx := transactionCtx(vm)
	ixCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return syscallErr(err)
	}

	programId, err := ixCtx.LastProgramKey(txCtx)
	if err != nil {
		return syscallErr(err)
	}

	txCtx.SetReturnData(programId, returnData)

	return syscallSuccess(0)
}

var SyscallSetReturnData = sbpf.SyscallFunc2(SyscallSetReturnDataImpl)

func castToPtr(obj any) uint64 {
	return uint64(uintptr(unsafe.Pointer(&obj)))
}

// SyscallGetProcessedSiblingInstructionImpl is an implementation of the sol_get_processed_sibling_instruction syscall
func SyscallGetProcessedSiblingInstructionImpl(vm sbpf.VM, index, metaAddr, programIdAddr, dataAddr, accountsAddr uint64) (uint64, error) {
	execCtx := executionCtx(vm)
	txCtx := transactionCtx(vm)

	err := execCtx.ComputeMeter.Consume(CUSyscallBaseCost)
	if err != nil {
		return syscallCuErr()
	}

	stackHeight := execCtx.StackHeight()
	instrTraceLen := txCtx.InstructionTraceLength()

	if instrTraceLen == 0 {
		return syscallSuccess(0)
	}

	var reverseIndexAtStackHeight uint64
	var instrCtxFound *InstructionCtx

	for indexInTrace := instrTraceLen; indexInTrace >= 0; indexInTrace-- {
		instrCtx, err := txCtx.InstructionCtxAtIndexInTrace(indexInTrace)
		if err != nil {
			return syscallErr(err)
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
			return syscallErr(err)
		}

		reader := bytes.NewReader(resultsHeaderBytes)

		var resultHeader ProcessedSiblingInstruction
		err = resultHeader.Unmarshal(reader)
		if err != nil {
			return syscallErr(err)
		}

		if resultHeader.DataLen == uint64(len(instrCtxFound.Data)) &&
			resultHeader.AccountsLen == instrCtxFound.NumberOfInstructionAccounts() {

			programIdBytes, err := vm.Translate(programIdAddr, solana.PublicKeyLength, true)
			if err != nil {
				return syscallErr(err)
			}

			data, err := vm.Translate(dataAddr, resultHeader.DataLen, true)
			if err != nil {
				return syscallErr(err)
			}

			accountMetaDataSize := safemath.SaturatingMulU64(resultHeader.AccountsLen, AccountMetaSize)
			accountMetaSliceBytes, err := vm.Translate(accountsAddr, accountMetaDataSize, true)
			if err != nil {
				return syscallErr(err)
			}

			reader.Reset(accountMetaSliceBytes)

			var accounts []AccountMeta
			for i := uint64(0); i < resultHeader.AccountsLen; i++ {
				var account AccountMeta
				err = account.Unmarshal(reader)
				if err != nil {
					return syscallErr(err)
				}
				accounts = append(accounts, account)
			}

			if !isNonOverlapping(metaAddr, ProcessedSiblingInstructionSize, programIdAddr, solana.PublicKeyLength) ||
				!isNonOverlapping(metaAddr, ProcessedSiblingInstructionSize, accountsAddr, accountMetaDataSize) ||
				!isNonOverlapping(metaAddr, ProcessedSiblingInstructionSize, dataAddr, resultHeader.DataLen) ||
				!isNonOverlapping(programIdAddr, solana.PublicKeyLength, dataAddr, resultHeader.DataLen) ||
				!isNonOverlapping(programIdAddr, solana.PublicKeyLength, accountsAddr, accountMetaDataSize) ||
				!isNonOverlapping(dataAddr, resultHeader.DataLen, accountsAddr, accountMetaDataSize) {
				return syscallErr(SyscallErrCopyOverlapping)
			}

			pk, err := instrCtxFound.LastProgramKey(transactionCtx(vm))
			if err != nil {
				return syscallErr(err)
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
					return syscallErr(err)
				}
				key, err := txCtx.KeyOfAccountAtIndex(idx)
				if err != nil {
					return syscallErr(err)
				}

				isSigner, err := instrCtxFound.IsInstructionAccountSigner(instrAcctIdx)
				if err != nil {
					return syscallErr(err)
				}

				isWritable, err := instrCtxFound.IsInstructionAccountWritable(instrAcctIdx)
				if err != nil {
					return syscallErr(err)
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

		return syscallSuccess(1) // true
	}

	return syscallSuccess(0) // false
}

var SyscallGetProcessedSiblingInstruction = sbpf.SyscallFunc5(SyscallGetProcessedSiblingInstructionImpl)
