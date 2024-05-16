package sealevel

import (
	bin "github.com/gagliardetto/binary"
	"k8s.io/klog/v2"
)

const (
	UpgradeableLoaderInstrTypeInitializeBuffer = iota
	UpgradeableLoaderInstrTypeWrite
	UpgradeableLoaderInstrTypeDeployWithMaxDataLen
	UpgradeableLoaderInstrTypeUpgrade
	UpgradeableLoaderInstrTypeSetAuthority
	UpgradeableLoaderInstrTypeClose
	UpgradeableLoaderInstrTypeExtendProgram
	UpgradeableLoaderInstrTypeSetAuthorityChecked
)

type UpgradeableLoaderInstrWrite struct {
	Offset uint32
	Bytes  []byte
}

type UpgradeLoaderInstrDeployWithMaxDataLen struct {
	MaxDataLen uint64
}

type UpgradeableLoaderInstrExtendProgram struct {
	AdditionalBytes uint32
}

func (write *UpgradeableLoaderInstrWrite) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	write.Offset, err = decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
	}

	write.Bytes, err = decoder.ReadByteSlice()
	return err
}

func (deploy *UpgradeLoaderInstrDeployWithMaxDataLen) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	deploy.MaxDataLen, err = decoder.ReadUint64(bin.LE)
	return err
}

func (extendProgram *UpgradeableLoaderInstrExtendProgram) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	extendProgram.AdditionalBytes, err = decoder.ReadUint32(bin.LE)
	return err
}

func BpfLoaderProgramExecute(execCtx *ExecutionCtx) error {
	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}
	programAcct, err := instrCtx.BorrowLastProgramAccount(txCtx)
	if err != nil {
		return err
	}

	if programAcct.Owner() == NativeLoaderAddr {
		programId, err := instrCtx.LastProgramKey(txCtx)
		if err != nil {
			return err
		}
		if programId == BpfLoaderUpgradeableAddr {
			err = execCtx.ComputeMeter.Consume(CUUpgradeableLoaderComputeUnits)
			if err != nil {
				return err
			}
			err = processUpgradeableLoaderInstruction(execCtx)
			return err
		} else if programId == BpfLoaderAddr {
			err = execCtx.ComputeMeter.Consume(CUDefaultLoaderComputeUnits)
			if err != nil {
				return err
			}
			return InstrErrUnsupportedProgramId
		} else if programId == BpfLoaderDeprecatedAddr {
			err = execCtx.ComputeMeter.Consume(CUDeprecatedLoaderComputeUnits)
			if err != nil {
				return err
			}
			return InstrErrUnsupportedProgramId
		} else {
			return InstrErrUnsupportedProgramId
		}
	}

	if !programAcct.IsExecutable(execCtx.GlobalCtx.Features) {
		return InstrErrUnsupportedProgramId
	}

	// TODO: program execution

	return nil
}

func processUpgradeableLoaderInstruction(execCtx *ExecutionCtx) error {
	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	instrData := instrCtx.Data

	programAcct, err := instrCtx.BorrowLastProgramAccount(txCtx)
	if err != nil {
		return err
	}

	klog.Infof("call to Upgradeable Loader with programID %s, instruction data: %#v", programAcct, instrData)

	return nil
}
