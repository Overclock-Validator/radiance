package sealevel

import (
	"bytes"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/safemath"
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

const (
	UpgradeableLoaderStateTypeUninitialized = iota
	UpgradeableLoaderStateTypeBuffer
	UpgradeableLoaderStateTypeProgram
	UpgradeableLoaderStateTypeProgramData
)

// instructions
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

// upgradeable loader account states
type UpgradeableLoaderStateBuffer struct {
	AuthorityAddress *solana.PublicKey
}

type UpgradeableLoaderStateProgram struct {
	ProgramDataAddress solana.PublicKey
}

type UpgradeableLoaderStateProgramData struct {
	Slot                    uint64
	UpgradeAuthorityAddress *solana.PublicKey
}

type UpgradeableLoaderState struct {
	Type        uint32
	Buffer      UpgradeableLoaderStateBuffer
	Program     UpgradeableLoaderStateProgram
	ProgramData UpgradeableLoaderStateProgramData
}

const upgradeableLoaderSizeOfBufferMetaData = 37

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

func (buffer *UpgradeableLoaderStateBuffer) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	hasPubkey, err := decoder.ReadBool()
	if err != nil {
		return err
	}

	if hasPubkey {
		pkBytes, err := decoder.ReadBytes(solana.PublicKeyLength)
		if err != nil {
			return err
		}
		pk := solana.PublicKeyFromBytes(pkBytes)
		buffer.AuthorityAddress = pk.ToPointer()
	}
	return nil
}

func (buffer *UpgradeableLoaderStateBuffer) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error
	if buffer.AuthorityAddress != nil {
		authAddr := *buffer.AuthorityAddress
		err = encoder.WriteBytes(authAddr.Bytes(), false)
	}
	return err
}

func (program *UpgradeableLoaderStateProgram) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	pkBytes, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(program.ProgramDataAddress[:], pkBytes)

	return nil
}

func (program *UpgradeableLoaderStateProgram) MarshalWithEncoder(encoder *bin.Encoder) error {
	err := encoder.WriteBytes(program.ProgramDataAddress[:], false)
	return err
}

func (programData *UpgradeableLoaderStateProgramData) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	programData.Slot, err = decoder.ReadUint64(bin.LE)
	if err != nil {
		return err
	}

	hasPubkey, err := decoder.ReadBool()
	if err != nil {
		return err
	}

	if hasPubkey {
		pkBytes, err := decoder.ReadBytes(solana.PublicKeyLength)
		if err != nil {
			return err
		}
		pk := solana.PublicKeyFromBytes(pkBytes)
		programData.UpgradeAuthorityAddress = pk.ToPointer()
	}

	return nil
}

func (programData *UpgradeableLoaderStateProgramData) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error
	err = encoder.WriteUint64(programData.Slot, bin.LE)
	if err != nil {
		return err
	}

	if programData.UpgradeAuthorityAddress != nil {
		upgradeAuthAddr := *programData.UpgradeAuthorityAddress
		err = encoder.WriteBytes(upgradeAuthAddr.Bytes(), false)
	}

	return err
}

func (state *UpgradeableLoaderState) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error

	state.Type, err = decoder.ReadUint32(bin.LE)
	if err != nil {
		return err
	}

	switch state.Type {
	case UpgradeableLoaderStateTypeUninitialized:
		{
			// nothing to deserialize
		}

	case UpgradeableLoaderStateTypeBuffer:
		{
			err = state.Buffer.UnmarshalWithDecoder(decoder)
		}

	case UpgradeableLoaderStateTypeProgram:
		{
			err = state.Program.UnmarshalWithDecoder(decoder)
		}

	case UpgradeableLoaderStateTypeProgramData:
		{
			err = state.ProgramData.UnmarshalWithDecoder(decoder)
		}

	default:
		{
			err = InstrErrInvalidAccountData
		}
	}

	return err
}

func (state *UpgradeableLoaderState) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error
	switch state.Type {
	case UpgradeableLoaderStateTypeUninitialized:
		{
			// nothing to deserialize
		}

	case UpgradeableLoaderStateTypeBuffer:
		{
			err = state.Buffer.MarshalWithEncoder(encoder)
		}

	case UpgradeableLoaderStateTypeProgram:
		{
			err = state.Program.MarshalWithEncoder(encoder)
		}

	case UpgradeableLoaderStateTypeProgramData:
		{
			err = state.ProgramData.MarshalWithEncoder(encoder)
		}

	default:
		{
			panic("attempting to serialize up invalid upgradeable loader state - programming error")
		}
	}
	return err
}

func unmarshalUpgradeableLoaderState(data []byte) (*UpgradeableLoaderState, error) {
	state := new(UpgradeableLoaderState)
	decoder := bin.NewBinDecoder(data)

	err := state.UnmarshalWithDecoder(decoder)
	if err != nil {
		return nil, InstrErrInvalidAccountData
	} else {
		return state, nil
	}
}

func marshalUpgradeableLoaderState(state *UpgradeableLoaderState) ([]byte, error) {
	buffer := new(bytes.Buffer)
	encoder := bin.NewBinEncoder(buffer)

	err := state.MarshalWithEncoder(encoder)
	if err != nil {
		return nil, err
	} else {
		return buffer.Bytes(), nil
	}
}

func setUpgradeableLoaderAccountState(acct *BorrowedAccount, state *UpgradeableLoaderState, f features.Features) error {
	acctStateBytes, err := marshalUpgradeableLoaderState(state)
	if err != nil {
		return err
	}

	err = acct.SetState(f, acctStateBytes)
	return err
}

func writeProgramData(execCtx *ExecutionCtx, programDataOffset uint64, bytes []byte) error {
	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	program, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}

	writeOffset := safemath.SaturatingAddU64(programDataOffset, uint64(len(bytes)))
	if uint64(len(program.Data())) < writeOffset {
		klog.Infof("write overflow. acct data len = %d, writeOffset = %d", len(program.Data()), writeOffset)
		return InstrErrAccountDataTooSmall
	}

	copy(program.Account.Data[programDataOffset:writeOffset], bytes)
	return nil
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

	decoder := bin.NewBinDecoder(instrData)

	instrType, err := decoder.ReadUint32(bin.LE)
	if err != nil {
		return InstrErrInvalidInstructionData
	}

	switch instrType {
	case UpgradeableLoaderInstrTypeInitializeBuffer:
		{
			err = instrCtx.CheckNumOfInstructionAccounts(2)
			if err != nil {
				return err
			}

			buffer, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
			if err != nil {
				return err
			}

			state, err := unmarshalUpgradeableLoaderState(buffer.Data())
			if err != nil {
				return err
			}

			if state.Type != UpgradeableLoaderStateTypeUninitialized {
				klog.Infof("Buffer account already initialized")
				return InstrErrAccountAlreadyInitialized
			}

			authorityKeyIdx, err := instrCtx.IndexOfInstructionAccountInTransaction(1)
			if err != nil {
				return err
			}

			authorityKey, err := txCtx.KeyOfAccountAtIndex(authorityKeyIdx)
			if err != nil {
				return err
			}

			state.Type = UpgradeableLoaderStateTypeBuffer
			state.Buffer.AuthorityAddress = authorityKey.ToPointer()

			err = setUpgradeableLoaderAccountState(buffer, state, execCtx.GlobalCtx.Features)
		}

	case UpgradeableLoaderInstrTypeWrite:
		{
			var write UpgradeableLoaderInstrWrite
			err = write.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}

			err = instrCtx.CheckNumOfInstructionAccounts(2)
			if err != nil {
				return err
			}

			buffer, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
			if err != nil {
				return err
			}

			state, err := unmarshalUpgradeableLoaderState(buffer.Data())
			if err != nil {
				return err
			}

			if state.Type == UpgradeableLoaderStateTypeBuffer {
				if state.Buffer.AuthorityAddress == nil {
					klog.Infof("Buffer is immutable")
					return InstrErrImmutable
				}

				authorityKeyIdx, err := instrCtx.IndexOfInstructionAccountInTransaction(1)
				if err != nil {
					return err
				}
				authorityKey, err := txCtx.KeyOfAccountAtIndex(authorityKeyIdx)
				if err != nil {
					return err
				}
				if *state.Buffer.AuthorityAddress != authorityKey {
					klog.Errorf("Incorrect buffer authority provided")
					return InstrErrIncorrectAuthority
				}

				isSigner, err := instrCtx.IsInstructionAccountSigner(1)
				if err != nil {
					klog.Infof("Buffer authority did not sign")
					return err
				}

				if !isSigner {
					return InstrErrMissingRequiredSignature
				}
			} else {
				klog.Infof("Invalid buffer account")
				return InstrErrInvalidAccountData
			}

			err = writeProgramData(execCtx, upgradeableLoaderSizeOfBufferMetaData+uint64(write.Offset), write.Bytes)
		}

	default:
		{
			err = InstrErrInvalidInstructionData
		}
	}

	return err
}
