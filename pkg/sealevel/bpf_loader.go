package sealevel

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/features"
	"go.firedancer.io/radiance/pkg/safemath"
	"go.firedancer.io/radiance/pkg/sbpf"
	"go.firedancer.io/radiance/pkg/sbpf/loader"
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

type UpgradeableLoaderInstrDeployWithMaxDataLen struct {
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
const upgradeableLoaderSizeOfProgram = 36
const upgradeableLoaderSizeOfProgramDataMetaData = 45
const upgradeableLoaderSizeOfUninitialized = 4

func upgradeableLoaderSizeOfProgramData(programLen uint64) uint64 {
	return safemath.SaturatingAddU64(upgradeableLoaderSizeOfProgramDataMetaData, programLen)
}

func upgradeableLoaderSizeOfBuffer(programLen uint64) uint64 {
	return safemath.SaturatingAddU64(upgradeableLoaderSizeOfBufferMetaData, programLen)
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

func (write *UpgradeableLoaderInstrWrite) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint32(UpgradeableLoaderInstrTypeWrite, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint32(write.Offset, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteBytes(write.Bytes, true)
	return err
}

func (deploy *UpgradeableLoaderInstrDeployWithMaxDataLen) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	deploy.MaxDataLen, err = decoder.ReadUint64(bin.LE)
	return err
}

func (deploy *UpgradeableLoaderInstrDeployWithMaxDataLen) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint32(UpgradeableLoaderInstrTypeDeployWithMaxDataLen, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(deploy.MaxDataLen, bin.LE)
	return err
}

func (extendProgram *UpgradeableLoaderInstrExtendProgram) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	extendProgram.AdditionalBytes, err = decoder.ReadUint32(bin.LE)
	return err
}

func (extendProgram *UpgradeableLoaderInstrExtendProgram) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint32(UpgradeableLoaderInstrTypeExtendProgram, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint32(extendProgram.AdditionalBytes, bin.LE)
	return err
}

func (buffer *UpgradeableLoaderStateBuffer) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	hasPubkey, err := ReadBool(decoder)
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
		err = encoder.WriteBool(true)
		if err != nil {
			return err
		}

		authAddr := *buffer.AuthorityAddress
		err = encoder.WriteBytes(authAddr.Bytes(), false)
	} else {
		err = encoder.WriteBool(false)
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

	hasPubkey, err := ReadBool(decoder)
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
		err = encoder.WriteBool(true)
		if err != nil {
			return err
		}

		upgradeAuthAddr := *programData.UpgradeAuthorityAddress
		err = encoder.WriteBytes(upgradeAuthAddr.Bytes(), false)
	} else {
		err = encoder.WriteBool(false)
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
	err := encoder.WriteUint32(state.Type, bin.LE)
	if err != nil {
		return err
	}

	switch state.Type {
	case UpgradeableLoaderStateTypeUninitialized:
		{
			// nothing to serialize
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

	newStateBytes := make([]byte, len(acct.Data()))
	copy(newStateBytes, acct.Data())
	copy(newStateBytes, acctStateBytes)

	err = acct.SetState(f, newStateBytes)
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
	defer program.Drop()

	writeOffset := safemath.SaturatingAddU64(programDataOffset, uint64(len(bytes)))
	if uint64(len(program.Data())) < writeOffset {
		klog.Infof("write overflow. acct data len = %d, writeOffset = %d", len(program.Data()), writeOffset)
		return InstrErrAccountDataTooSmall
	}

	data, err := program.DataMutable(execCtx.GlobalCtx.Features)
	if err != nil {
		return err
	}

	copy(data[programDataOffset:writeOffset], bytes)
	return nil
}

func deployProgram(execCtx *ExecutionCtx, programData []byte) error {
	syscallRegistry := Syscalls(&execCtx.GlobalCtx.Features, true)

	loader, err := loader.NewLoaderWithSyscalls(programData, &syscallRegistry, true)
	if err != nil {
		klog.Infof("failed to create loader")
		return err
	}

	program, err := loader.Load()
	if err != nil {
		klog.Infof("failed to load program")
		return err
	}

	err = program.Verify()
	if err != nil {
		klog.Infof("failed to verify program")
		return err
	}

	return nil
}

func calculateHeapCost(heapSize uint32, heapCost uint64) uint64 {
	KiBiByteMulPages := uint64(1024 * 32)
	KiBiByteMulPagesSub1 := KiBiByteMulPages - 1
	roundedHeapSize := uint64(heapSize)
	roundedHeapSize = roundedHeapSize + KiBiByteMulPagesSub1
	roundedHeapSize = ((roundedHeapSize / KiBiByteMulPagesSub1) * heapCost)
	return roundedHeapSize
}

const MaxInstructionAccounts = 255
const MaxPermittedDataIncrease = 1024 * 10

type serializeAcct struct {
	isDuplicate bool
	indexOfAcct uint64
	acct        *BorrowedAccount
}

type serializedAcctMetadata struct {
	originalDataLen uint64
	vmDataAddr      uint64
	vmKeyAddr       uint64
	vmLamportsAddr  uint64
	vmOwnerAddr     uint64
}

func serializeParametersAligned(execCtx *ExecutionCtx) ([]byte, []uint64, error) {
	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return nil, nil, err
	}

	numIxAccts := instrCtx.NumberOfInstructionAccounts()
	if numIxAccts > MaxInstructionAccounts {
		return nil, nil, InstrErrMaxAccountsExceeded
	}

	programAcct, err := instrCtx.BorrowLastProgramAccount(txCtx)
	if err != nil {
		return nil, nil, err
	}
	programId := programAcct.Key()
	programAcct.Drop()

	instrData := instrCtx.Data
	var preLens []uint64

	accts := make([]serializeAcct, 0)
	for instrAcctIdx := uint64(0); instrAcctIdx < instrCtx.NumberOfInstructionAccounts(); instrAcctIdx++ {
		isDupe, idxInCallee, err := instrCtx.IsInstructionAccountDuplicate(instrAcctIdx)
		if err != nil {
			return nil, nil, err
		}
		if isDupe {
			sa := serializeAcct{isDuplicate: true, indexOfAcct: idxInCallee}
			accts = append(accts, sa)
		} else {
			acct, err := instrCtx.BorrowInstructionAccount(txCtx, instrAcctIdx)
			if err != nil {
				return nil, nil, err
			}
			defer acct.Drop()

			sa := serializeAcct{indexOfAcct: instrAcctIdx, acct: acct}
			accts = append(accts, sa)
		}
	}

	acctsMetaData := make([]serializedAcctMetadata, len(accts))

	size := uint64(8)

	for _, acct := range accts {
		size += 1 // dup

		if acct.isDuplicate {
			size += 7 // padding to 64-bit aligned
		} else {
			dataLen := uint64(len(acct.acct.Data()))
			alignmentMask := uint64(7) // (alignment - 1)
			alignedDataLen := dataLen + (-dataLen & alignmentMask)

			size += 1                      // is_signer
			size += 1                      // is_writable
			size += 1                      // executable
			size += 4                      // original_data_len
			size += solana.PublicKeyLength // key
			size += solana.PublicKeyLength // owner
			size += 8                      // lamports
			size += 8                      // data len
			size += MaxPermittedDataIncrease
			size += 8 // rent epoch
			size += alignedDataLen
		}
	}

	size += 8 + uint64(len(instrData)) // data len
	size += solana.PublicKeyLength     // program id

	var serializedData []byte
	serializedData = binary.LittleEndian.AppendUint64(serializedData, uint64(len(accts)))

	for _, acct := range accts {
		borrowedAcct := acct.acct
		if acct.isDuplicate { // duplicate
			position := acct.indexOfAcct
			acctsMetaData = append(acctsMetaData, acctsMetaData[position])
			serializedData = append(serializedData, byte(position))
			for count := 0; count < 7; count++ {
				serializedData = append(serializedData, 0)
			}
		} else { // not a duplicate
			serializedData = append(serializedData, 0xff)

			if borrowedAcct.IsSigner() {
				serializedData = append(serializedData, 1)
			} else {
				serializedData = append(serializedData, 0)
			}

			if borrowedAcct.IsWritable() {
				serializedData = append(serializedData, 1)
			} else {
				serializedData = append(serializedData, 0)
			}

			if borrowedAcct.IsExecutable() {
				serializedData = append(serializedData, 1)
			} else {
				serializedData = append(serializedData, 0)
			}

			for count := 0; count < 4; count++ {
				serializedData = append(serializedData, 0)
			}

			// acct key
			acctKey := [32]byte(borrowedAcct.Key())
			acctKeySlice := acctKey[:]
			serializedData = append(serializedData, acctKeySlice...)

			// owner
			owner := [32]byte(borrowedAcct.Owner())
			ownerSlice := owner[:]
			serializedData = append(serializedData, ownerSlice...)

			// lamports
			serializedData = binary.LittleEndian.AppendUint64(serializedData, borrowedAcct.Lamports())

			// acct data len
			dataLen := uint64(len(borrowedAcct.Data()))
			preLens = append(preLens, dataLen)
			serializedData = binary.LittleEndian.AppendUint64(serializedData, dataLen)

			// data in account
			serializedData = append(serializedData, borrowedAcct.Data()...)

			padding := ReallocSpace
			if offset := len(serializedData) % ReallocAlign; offset != 0 {
				padding += ReallocAlign - offset
			}
			for count := 0; count < padding; count++ {
				serializedData = append(serializedData, 0)
			}

			// rent epoch
			serializedData = binary.LittleEndian.AppendUint64(serializedData, borrowedAcct.RentEpoch())
		}
	}

	// instr data len
	serializedData = binary.LittleEndian.AppendUint64(serializedData, uint64(len(instrData)))

	// instr data
	serializedData = append(serializedData, instrData...)

	// program id
	programIdSlice := programId[:]
	serializedData = append(serializedData, programIdSlice...)

	// sanity check for expected len vs. serialized data size
	if uint64(len(serializedData)) != size {
		panic("mismatch between serialized data and expected length")
	}

	return serializedData, preLens, nil
}

func deserializeParametersAligned(execCtx *ExecutionCtx, parameterBytes []byte, preLens []uint64) error {
	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	var off uint64

	off += 8 // number of accounts
	for instrAcctIdx := uint64(0); instrAcctIdx < instrCtx.NumberOfInstructionAccounts(); instrAcctIdx++ {
		preLen := preLens[instrAcctIdx]

		isDupe, _, err := instrCtx.IsInstructionAccountDuplicate(instrAcctIdx)
		if err != nil {
			return err
		}
		off += 1 // position
		if isDupe {
			off += 7 // padding to 64-bit aligned
		} else {
			borrowedAcct, err := instrCtx.BorrowInstructionAccount(txCtx, instrAcctIdx)
			if err != nil {
				return err
			}
			defer borrowedAcct.Drop()

			off += 1                      // is_signer
			off += 1                      // is_writable
			off += 1                      // executable
			off += 4                      // original_data_len
			off += solana.PublicKeyLength // key

			if uint64(len(parameterBytes)) < (off + solana.PublicKeyLength) {
				return InstrErrInvalidArgument
			}

			owner := parameterBytes[off : off+solana.PublicKeyLength]
			off += solana.PublicKeyLength // owner

			if uint64(len(parameterBytes)) < (off + 8) {
				return InstrErrInvalidArgument
			}
			lamports := binary.LittleEndian.Uint64(parameterBytes[off:])

			if borrowedAcct.Lamports() != lamports {
				err = borrowedAcct.SetLamports(lamports, execCtx.GlobalCtx.Features)
				if err != nil {
					return err
				}
			}
			off += 8 // lamports

			if uint64(len(parameterBytes)) < (off + 8) {
				return InstrErrInvalidArgument
			}
			postLen := binary.LittleEndian.Uint64(parameterBytes[off:])
			off += 8 // data length

			if safemath.SaturatingSubU64(postLen, preLen) > MaxPermittedDataIncrease ||
				postLen > MaxPermittedDataIncrease {
				return InstrErrInvalidRealloc
			}

			alignmentMask := uint64(7) // (alignment - 1)
			alignmentOffset := -preLen & alignmentMask

			if uint64(len(parameterBytes)) < (off + postLen) {
				return InstrErrInvalidArgument
			}
			data := parameterBytes[off : off+postLen]

			resizeErr := borrowedAcct.CanDataBeResized(postLen)
			changedErr := borrowedAcct.DataCanBeChanged(execCtx.GlobalCtx.Features)

			if resizeErr != nil || changedErr != nil {
				acctBytes := borrowedAcct.Data()
				if len(acctBytes) != len(data) {
					return fmt.Errorf("data cannot be changed, but did anyway")
				}
				for count := range acctBytes {
					if acctBytes[count] != data[count] {
						return fmt.Errorf("data cannot be changed, but did anyway")
					}
				}
			} else {
				err = borrowedAcct.SetData(execCtx.GlobalCtx.Features, data)
				if err != nil {
					return err
				}
			}

			off += preLen

			off += MaxPermittedDataIncrease
			off += alignmentOffset
			off += 8 // rent epoch

			ownerPk := solana.PublicKeyFromBytes(owner)
			if borrowedAcct.Owner() != ownerPk {
				err = borrowedAcct.SetOwner(execCtx.GlobalCtx.Features, ownerPk)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func executeProgram(execCtx *ExecutionCtx, programData []byte) error {
	klog.Infof("bpf loader - executeProgram")

	syscallRegistry := Syscalls(&execCtx.GlobalCtx.Features, false)

	loader, err := loader.NewLoaderWithSyscalls(programData, &syscallRegistry, false)
	if err != nil {
		return err
	}

	program, err := loader.Load()
	if err != nil {
		return err
	}

	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	programAcct, err := instrCtx.BorrowLastProgramAccount(txCtx)
	if err != nil {
		return err
	}
	programId := programAcct.Key()
	programAcct.Drop()

	computeRemainingPrev := execCtx.ComputeMeter.Remaining()
	heapSize := execCtx.TransactionContext.HeapSize
	heapCostResult := calculateHeapCost(heapSize, CUHeapCostDefault)

	err = execCtx.ComputeMeter.Consume(heapCostResult)
	if err != nil {
		return err
	}

	parameterBytes, preLens, err := serializeParametersAligned(execCtx)
	if err != nil {
		return err
	}

	opts := &sbpf.VMOpts{
		HeapMax:  int(execCtx.TransactionContext.HeapSize),
		Input:    parameterBytes,
		Syscalls: syscallRegistry,
		Context:  execCtx,
	}

	interpreter := sbpf.NewInterpreter(nil, program, opts)
	ret, runErr := interpreter.Run()

	computeUnitsConsumed := computeRemainingPrev - execCtx.ComputeMeter.Remaining()
	klog.Infof("Program %s consumed %d of %d compute units", programId, computeUnitsConsumed, computeRemainingPrev)

	if runErr != nil {
		klog.Infof("program execution result: %s", runErr)
	} else {
		klog.Infof("program execution was successful and returned %d", ret)
	}

	returnedDataProgId, returnData := execCtx.TransactionContext.ReturnData()
	if len(returnData) != 0 {
		encodedStr := base64.StdEncoding.EncodeToString(returnData)
		klog.Infof("Program return %s %s", returnedDataProgId, encodedStr)
	}

	// deserialize data
	if runErr == nil {
		err = deserializeParametersAligned(execCtx, parameterBytes, preLens)
		if err != nil {
			klog.Infof("failed to deserialize, %s", err)
			return InstrErrInvalidArgument
		}
	}

	// TODO: proper handling of errors returned from VM

	return runErr
}

func BpfLoaderProgramExecute(execCtx *ExecutionCtx) error {
	klog.Infof("BpfLoaderProgramExecute")

	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	programAcct, err := instrCtx.BorrowLastProgramAccount(txCtx)
	if err != nil {
		return err
	}
	defer programAcct.Drop()

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
			err = ProcessUpgradeableLoaderInstruction(execCtx)
			return err
		} else if programId == BpfLoader2Addr {
			err = execCtx.ComputeMeter.Consume(CUDefaultLoaderComputeUnits)
			if err != nil {
				return err
			}
			klog.Infof("BPF loader 2 mgmt no longer supported")
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

	if !programAcct.IsExecutable() {
		klog.Infof("program is not executable")
		return InstrErrUnsupportedProgramId
	}

	var programBytes []byte

	programOwner := programAcct.Owner()

	if programOwner == BpfLoader2Addr || programOwner == BpfLoaderDeprecatedAddr {
		programBytes = programAcct.Data()
		programAcct.Drop()
	} else if programOwner == BpfLoaderUpgradeableAddr {
		programAcctState, err := unmarshalUpgradeableLoaderState(programAcct.Data())
		if err != nil {
			return err
		}

		programAcct.Drop()

		programDataPubkey := [32]byte(programAcctState.Program.ProgramDataAddress)
		programDataAcct, err := execCtx.Accounts.GetAccount(&programDataPubkey)
		programDataAcctState, err := unmarshalUpgradeableLoaderState(programDataAcct.Data)
		if err != nil {
			return err
		}

		if programDataAcctState.Type == UpgradeableLoaderStateTypeUninitialized {
			return InstrErrInvalidAccountData
		}

		programDataSlot := programDataAcctState.ProgramData.Slot
		if programDataSlot >= execCtx.SlotCtx.Slot {
			return InstrErrInvalidAccountData
		}

		programBytes = programDataAcct.Data[upgradeableLoaderSizeOfProgramDataMetaData:]
	} else {
		return InstrErrUnsupportedProgramId
	}

	err = executeProgram(execCtx, programBytes)

	return err
}

func UpgradeableLoaderInitializeBuffer(execCtx *ExecutionCtx, txCtx *TransactionCtx, instrCtx *InstructionCtx) error {
	klog.Infof("InitializeBuffer instr")
	err := instrCtx.CheckNumOfInstructionAccounts(2)
	if err != nil {
		return err
	}

	buffer, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}
	defer buffer.Drop()

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

	return err
}

func UpgradeableLoaderWrite(execCtx *ExecutionCtx, txCtx *TransactionCtx, instrCtx *InstructionCtx, write UpgradeableLoaderInstrWrite) error {
	klog.Infof("Write instr")

	err := instrCtx.CheckNumOfInstructionAccounts(2)
	if err != nil {
		return err
	}

	buffer, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}
	defer buffer.Drop()

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

	buffer.Drop()

	err = writeProgramData(execCtx, upgradeableLoaderSizeOfBufferMetaData+uint64(write.Offset), write.Bytes)
	return err
}

func UpgradeableLoaderDeployWithMaxDataLen(execCtx *ExecutionCtx, txCtx *TransactionCtx, instrCtx *InstructionCtx, deploy UpgradeableLoaderInstrDeployWithMaxDataLen) error {
	err := instrCtx.CheckNumOfInstructionAccounts(4)
	if err != nil {
		return err
	}

	payerKeyIdx, err := instrCtx.IndexOfInstructionAccountInTransaction(0)
	if err != nil {
		return err
	}
	payerKey, err := txCtx.KeyOfAccountAtIndex(payerKeyIdx)
	if err != nil {
		return err
	}

	programDataKeyIdx, err := instrCtx.IndexOfInstructionAccountInTransaction(1)
	if err != nil {
		return err
	}
	programDataKey, err := txCtx.KeyOfAccountAtIndex(programDataKeyIdx)
	if err != nil {
		return err
	}

	err = checkAcctForRentSysvar(txCtx, instrCtx, 4)
	if err != nil {
		return err
	}

	rent, err := ReadRentSysvar(&execCtx.Accounts)
	if err != nil {
		return err
	}

	err = checkAcctForClockSysvar(txCtx, instrCtx, 5)
	if err != nil {
		return err
	}

	clock, err := ReadClockSysvar(&execCtx.Accounts)
	if err != nil {
		return err
	}

	err = instrCtx.CheckNumOfInstructionAccounts(8)
	if err != nil {
		return err
	}

	var authorityKey *solana.PublicKey
	authorityIdx, err := instrCtx.IndexOfInstructionAccountInTransaction(7)
	if err == nil {
		k, err := txCtx.KeyOfAccountAtIndex(authorityIdx)
		if err != nil {
			return err
		}
		authorityKey = k.ToPointer()
	}

	// validate program account
	program, err := instrCtx.BorrowInstructionAccount(txCtx, 2)
	if err != nil {
		return err
	}
	defer program.Drop()

	programAcctState, err := unmarshalUpgradeableLoaderState(program.Data())
	if err != nil {
		return err
	}

	if programAcctState.Type != UpgradeableLoaderStateTypeUninitialized {
		return InstrErrAccountAlreadyInitialized
	}

	if len(program.Data()) < upgradeableLoaderSizeOfProgram {
		return InstrErrAccountDataTooSmall
	}

	if program.Lamports() < rent.MinimumBalance(uint64(len(program.Data()))) {
		return InstrErrExecutableAccountNotRentExempt
	}

	newProgramId := program.Key()
	program.Drop()

	// validate buffer account
	buffer, err := instrCtx.BorrowInstructionAccount(txCtx, 3)
	if err != nil {
		return err
	}
	defer buffer.Drop()

	bufferAcctState, err := unmarshalUpgradeableLoaderState(buffer.Data())
	if err != nil {
		return err
	}

	if bufferAcctState.Type != UpgradeableLoaderStateTypeBuffer {
		return InstrErrInvalidArgument
	}

	if bufferAcctState.Buffer.AuthorityAddress != nil && authorityKey != nil &&
		*bufferAcctState.Buffer.AuthorityAddress != *authorityKey {
		return InstrErrIncorrectAuthority
	}

	isSigner, err := instrCtx.IsInstructionAccountSigner(7)
	if err != nil {
		return err
	}
	if !isSigner {
		return InstrErrMissingRequiredSignature
	}

	bufferKey := buffer.Key()
	bufferDataOffset := uint64(upgradeableLoaderSizeOfBufferMetaData)
	bufferDataLen := safemath.SaturatingSubU64(uint64(len(buffer.Data())), bufferDataOffset)
	programDataDataOffset := uint64(upgradeableLoaderSizeOfProgramDataMetaData)
	programDataLen := upgradeableLoaderSizeOfProgramData(deploy.MaxDataLen)

	if uint64(len(buffer.Account.Data)) < upgradeableLoaderSizeOfBufferMetaData || bufferDataLen == 0 {
		return InstrErrInvalidAccountData
	}

	buffer.Drop()

	if deploy.MaxDataLen < bufferDataLen {
		return InstrErrAccountDataTooSmall
	}

	if programDataLen > MaxPermittedDataLength {
		return InstrErrInvalidArgument
	}

	seed := make([][]byte, 1)
	seed[0] = make([]byte, solana.PublicKeyLength)
	copy(seed[0], newProgramId[:])

	programId, err := instrCtx.LastProgramKey(txCtx)
	if err != nil {
		return err
	}

	derivedAddr, bumpSeed, _ := solana.FindProgramAddress(seed, programId)
	if derivedAddr != programDataKey {
		return InstrErrInvalidArgument
	}

	buffer, err = instrCtx.BorrowInstructionAccount(txCtx, 3)
	if err != nil {
		return err
	}

	payer, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}
	defer payer.Drop()

	payer.CheckedAddLamports(buffer.Lamports(), execCtx.GlobalCtx.Features)
	buffer.SetLamports(0, execCtx.GlobalCtx.Features)

	buffer.Drop()
	payer.Drop()

	//ownerId := programId

	var lamports uint64
	minBalance := rent.MinimumBalance(programDataLen)
	if minBalance > 1 {
		lamports = minBalance
	} else {
		lamports = 1
	}
	createAcctInstr := newCreateAccountInstruction(payerKey, programDataKey, lamports, programDataLen, programId)
	createAcctInstr.Accounts = append(createAcctInstr.Accounts, AccountMeta{Pubkey: bufferKey, IsSigner: false, IsWritable: true})

	callerProgramId, err := instrCtx.LastProgramKey(txCtx)
	if err != nil {
		return err
	}

	var seeds [][]byte
	seeds = append(seeds, newProgramId[:])
	seeds = append(seeds, []byte{bumpSeed})

	signer, err := solana.CreateProgramAddress(seeds, callerProgramId)
	if err != nil {
		return err
	}

	var signers []solana.PublicKey
	signers = append(signers, signer)

	err = execCtx.NativeInvoke(*createAcctInstr, signers)
	if err != nil {
		return err
	}

	bufferData := buffer.Data()
	if uint64(len(bufferData)) < bufferDataOffset {
		return InstrErrAccountDataTooSmall
	}

	buffer, err = instrCtx.BorrowInstructionAccount(txCtx, 3)
	if err != nil {
		return err
	}

	err = deployProgram(execCtx, bufferData[bufferDataOffset:])
	if err != nil {
		return InstrErrInvalidAccountData
	}

	buffer.Drop()

	programData, err := instrCtx.BorrowInstructionAccount(txCtx, 1)
	if err != nil {
		return err
	}
	defer programData.Drop()

	programDataState := &UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeProgramData,
		ProgramData: UpgradeableLoaderStateProgramData{Slot: clock.Slot, UpgradeAuthorityAddress: authorityKey}}

	err = setUpgradeableLoaderAccountState(programData, programDataState, execCtx.GlobalCtx.Features)
	if err != nil {
		return err
	}

	dstEnd := safemath.SaturatingAddU64(programDataDataOffset, bufferDataLen)
	if uint64(len(programData.Data())) < dstEnd {
		return InstrErrAccountDataTooSmall
	}
	if uint64(len(programData.Data())) < bufferDataOffset {
		return InstrErrAccountDataTooSmall
	}

	dstSlice, err := programData.DataMutable(execCtx.GlobalCtx.Features)
	if err != nil {
		return err
	}

	buffer, err = instrCtx.BorrowInstructionAccount(txCtx, 3)
	if err != nil {
		return err
	}

	srcSlice := buffer.Account.Data[bufferDataOffset:]
	copy(dstSlice[programDataDataOffset:dstEnd], srcSlice)

	err = buffer.SetDataLength(upgradeableLoaderSizeOfBuffer(0), execCtx.GlobalCtx.Features)
	if err != nil {
		return err
	}

	buffer.Drop()
	programData.Drop()

	programState := &UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeProgram,
		Program: UpgradeableLoaderStateProgram{ProgramDataAddress: programDataKey}}

	program, err = instrCtx.BorrowInstructionAccount(txCtx, 2)
	if err != nil {
		return err
	}

	err = setUpgradeableLoaderAccountState(program, programState, execCtx.GlobalCtx.Features)
	if err != nil {
		return err
	}

	if !execCtx.GlobalCtx.Features.IsActive(features.DeprecateExecutableMetaUpdateInBpfLoader) {
		err = program.SetExecutable(true)
		if err != nil {
			return err
		}
	}

	klog.Infof("deployed program: %s", newProgramId)

	return nil
}

func UpgradeableLoaderUpgrade(execCtx *ExecutionCtx, txCtx *TransactionCtx, instrCtx *InstructionCtx) error {
	err := instrCtx.CheckNumOfInstructionAccounts(3)
	if err != nil {
		return err
	}

	programDataKeyIdx, err := instrCtx.IndexOfInstructionAccountInTransaction(0)
	if err != nil {
		return err
	}
	programDataKey, err := txCtx.KeyOfAccountAtIndex(programDataKeyIdx)
	if err != nil {
		return err
	}

	err = checkAcctForRentSysvar(txCtx, instrCtx, 4)
	if err != nil {
		return err
	}

	rent, err := ReadRentSysvar(&execCtx.Accounts)
	if err != nil {
		return err
	}

	err = checkAcctForClockSysvar(txCtx, instrCtx, 5)
	if err != nil {
		return err
	}

	clock, err := ReadClockSysvar(&execCtx.Accounts)
	if err != nil {
		return err
	}

	err = instrCtx.CheckNumOfInstructionAccounts(7)
	if err != nil {
		return err
	}

	authorityKeyIdx, err := instrCtx.IndexOfInstructionAccountInTransaction(6)
	if err != nil {
		return err
	}
	authorityKey, err := txCtx.KeyOfAccountAtIndex(authorityKeyIdx)
	if err != nil {
		return err
	}

	program, err := instrCtx.BorrowInstructionAccount(txCtx, 1)
	if err != nil {
		return err
	}
	defer program.Drop()

	if !program.IsExecutable() {
		return InstrErrAccountNotExecutable
	}

	if !program.IsWritable() {
		return InstrErrInvalidArgument
	}

	programId, err := instrCtx.LastProgramKey(txCtx)
	if err != nil {
		return err
	}
	if program.Owner() != programId {
		return InstrErrIncorrectProgramId
	}

	programState, err := unmarshalUpgradeableLoaderState(program.Data())
	if err != nil {
		return err
	}

	if programState.Type == UpgradeableLoaderStateTypeProgram {
		if programState.Program.ProgramDataAddress != programDataKey {
			return InstrErrInvalidArgument
		}
	} else {
		return InstrErrInvalidAccountData
	}

	program.Drop()

	buffer, err := instrCtx.BorrowInstructionAccount(txCtx, 2)
	if err != nil {
		return err
	}
	defer buffer.Drop()

	bufferState, err := unmarshalUpgradeableLoaderState(buffer.Data())
	if err != nil {
		return err
	}

	if bufferState.Type == UpgradeableLoaderStateTypeBuffer {
		if bufferState.Buffer.AuthorityAddress == nil || *bufferState.Buffer.AuthorityAddress != authorityKey {
			return InstrErrIncorrectAuthority
		}
		isSigner, err := instrCtx.IsInstructionAccountSigner(6)
		if err != nil {
			return err
		}
		if !isSigner {
			return InstrErrMissingRequiredSignature
		}
	} else {
		return InstrErrInvalidArgument
	}

	bufferLamports := buffer.Lamports()
	bufferDataOffset := uint64(upgradeableLoaderSizeOfBufferMetaData)
	bufferDataLen := safemath.SaturatingSubU64(uint64(len(buffer.Data())), bufferDataOffset)
	if len(buffer.Data()) < upgradeableLoaderSizeOfBufferMetaData || bufferDataLen == 0 {
		return InstrErrInvalidAccountData
	}

	buffer.Drop()

	programData, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}
	defer programData.Drop()

	var programDataBalanceRequired uint64
	minBalance := rent.MinimumBalance(uint64(len(programData.Data())))
	if minBalance > 1 {
		programDataBalanceRequired = minBalance
	} else {
		programDataBalanceRequired = 1
	}

	if len(programData.Data()) < int(upgradeableLoaderSizeOfProgramData(bufferDataLen)) {
		return InstrErrAccountDataTooSmall
	}

	if safemath.SaturatingAddU64(programData.Lamports(), bufferLamports) < programDataBalanceRequired {
		return InstrErrInsufficientFunds
	}

	programDataState, err := unmarshalUpgradeableLoaderState(programData.Data())
	if err != nil {
		return err
	}

	if programDataState.Type == UpgradeableLoaderStateTypeProgramData {
		if clock.Slot == programDataState.ProgramData.Slot {
			return InstrErrInvalidArgument
		}
		if programDataState.ProgramData.UpgradeAuthorityAddress == nil {
			return InstrErrImmutable
		}
		if *programDataState.ProgramData.UpgradeAuthorityAddress != authorityKey {
			return InstrErrIncorrectAuthority
		}
		isSigner, err := instrCtx.IsInstructionAccountSigner(6)
		if err != nil {
			return err
		}
		if !isSigner {
			return InstrErrMissingRequiredSignature
		}
	} else {
		return InstrErrInvalidAccountData
	}
	programData.Drop()

	buffer, err = instrCtx.BorrowInstructionAccount(txCtx, 2)
	if err != nil {
		return err
	}

	bufferData := buffer.Data()
	if uint64(len(bufferData)) < bufferDataOffset {
		return InstrErrAccountDataTooSmall
	}
	err = deployProgram(execCtx, bufferData[bufferDataOffset:])
	if err != nil {
		return InstrErrInvalidAccountData
	}
	buffer.Drop()

	programData, err = instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}

	programDataNewState := &UpgradeableLoaderState{ProgramData: UpgradeableLoaderStateProgramData{Slot: clock.Slot, UpgradeAuthorityAddress: &authorityKey}}
	err = setUpgradeableLoaderAccountState(programData, programDataNewState, execCtx.GlobalCtx.Features)
	if err != nil {
		return err
	}

	programDataDataOffset := uint64(upgradeableLoaderSizeOfProgramDataMetaData)
	dstEnd := safemath.SaturatingAddU64(programDataDataOffset, bufferDataLen)
	if uint64(len(programData.Data())) < dstEnd {
		return InstrErrAccountDataTooSmall
	}
	if uint64(len(programData.Data())) < bufferDataOffset {
		return InstrErrAccountDataTooSmall
	}

	dstSlice := programData.Account.Data[programDataDataOffset:dstEnd]

	buffer, err = instrCtx.BorrowInstructionAccount(txCtx, 2)
	if err != nil {
		return err
	}

	srcSlice := buffer.Account.Data[bufferDataOffset:]
	copy(dstSlice, srcSlice)

	programDataFillSlice := programData.Account.Data[dstEnd:]
	for i := range programDataFillSlice {
		programDataFillSlice[i] = 0
	}

	spill, err := instrCtx.BorrowInstructionAccount(txCtx, 3)
	if err != nil {
		return err
	}
	defer spill.Drop()

	spillLamports := safemath.SaturatingSubU64(safemath.SaturatingAddU64(programData.Lamports(), bufferLamports), programDataBalanceRequired)
	err = spill.CheckedAddLamports(spillLamports, execCtx.GlobalCtx.Features)
	if err != nil {
		return err
	}

	err = buffer.SetLamports(0, execCtx.GlobalCtx.Features)
	if err != nil {
		return err
	}
	err = programData.SetLamports(programDataBalanceRequired, execCtx.GlobalCtx.Features)
	if err != nil {
		return err
	}

	err = buffer.SetDataLength(upgradeableLoaderSizeOfBuffer(0), execCtx.GlobalCtx.Features)
	if err != nil {
		return err
	}

	klog.Infof("upgraded program %s", program.Key())
	return nil
}

func UpgradeableLoaderSetAuthority(execCtx *ExecutionCtx, txCtx *TransactionCtx, instrCtx *InstructionCtx) error {
	klog.Infof("SetAuthority instr")

	err := instrCtx.CheckNumOfInstructionAccounts(2)
	if err != nil {
		return err
	}

	account, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}
	defer account.Drop()

	presentAuthorityKeyIdx, err := instrCtx.IndexOfInstructionAccountInTransaction(1)
	if err != nil {
		return err
	}

	presentAuthorityKey, err := txCtx.KeyOfAccountAtIndex(presentAuthorityKeyIdx)
	if err != nil {
		return err
	}

	var newAuthority *solana.PublicKey
	newAuthorityIdx, err := instrCtx.IndexOfInstructionAccountInTransaction(2)
	if err == nil {
		pk, err := txCtx.KeyOfAccountAtIndex(newAuthorityIdx)
		if err == nil {
			newAuthority = &pk
		}
	}

	accountState, err := unmarshalUpgradeableLoaderState(account.Data())
	if err != nil {
		return err
	}

	switch accountState.Type {
	case UpgradeableLoaderStateTypeBuffer:
		{
			klog.Infof("buffer account")
			if newAuthority == nil {
				klog.Infof("buffer authority not optional")
				return InstrErrIncorrectAuthority
			}

			if accountState.Buffer.AuthorityAddress == nil {
				klog.Infof("buffer is immutable")
				return InstrErrImmutable
			}

			if *accountState.Buffer.AuthorityAddress != presentAuthorityKey {
				klog.Infof("incorrect buffer authority provided")
				return InstrErrIncorrectAuthority
			}

			isSigner, err := instrCtx.IsInstructionAccountSigner(1)
			if err != nil {
				return err
			}

			if !isSigner {
				klog.Infof("upgrade authority did not sign")
				return InstrErrMissingRequiredSignature
			}

			accountState.Buffer.AuthorityAddress = newAuthority
			err = setUpgradeableLoaderAccountState(account, accountState, execCtx.GlobalCtx.Features)
			if err != nil {
				return err
			}
		}

	case UpgradeableLoaderStateTypeProgramData:
		{
			klog.Infof("ProgramData account")
			if accountState.ProgramData.UpgradeAuthorityAddress == nil {
				klog.Infof("program not upgradeable")
				return InstrErrImmutable
			}

			if *accountState.ProgramData.UpgradeAuthorityAddress != presentAuthorityKey {
				klog.Infof("incorrect upgrade authority provided")
				return InstrErrIncorrectAuthority
			}

			isSigner, err := instrCtx.IsInstructionAccountSigner(1)
			if err != nil {
				return err
			}

			if !isSigner {
				klog.Infof("upgrade authority did not sign")
				return InstrErrMissingRequiredSignature
			}

			accountState.ProgramData.UpgradeAuthorityAddress = newAuthority
			err = setUpgradeableLoaderAccountState(account, accountState, execCtx.GlobalCtx.Features)
			if err != nil {
				return err
			}
		}

	default:
		{
			klog.Infof("account does not support authorities")
			return InstrErrInvalidArgument
		}
	}

	var na string
	if newAuthority != nil {
		na = newAuthority.String()
	} else {
		na = "nil"
	}
	klog.Infof("new authority: %s", na)

	return nil
}

func UpgradeableLoaderSetAuthorityChecked(execCtx *ExecutionCtx, txCtx *TransactionCtx, instrCtx *InstructionCtx) error {
	klog.Infof("SetAuthorityChecked instr")

	if !execCtx.GlobalCtx.Features.IsActive(features.EnableBpfLoaderSetAuthorityCheckedIx) {
		return InstrErrInvalidInstructionData
	}

	err := instrCtx.CheckNumOfInstructionAccounts(3)
	if err != nil {
		return err
	}

	account, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}
	defer account.Drop()

	presentAuthorityKeyIdx, err := instrCtx.IndexOfInstructionAccountInTransaction(1)
	if err != nil {
		return err
	}

	presentAuthorityKey, err := txCtx.KeyOfAccountAtIndex(presentAuthorityKeyIdx)
	if err != nil {
		return err
	}

	newAuthorityIdx, err := instrCtx.IndexOfInstructionAccountInTransaction(2)
	if err != nil {
		return err
	}

	newAuthority, err := txCtx.KeyOfAccountAtIndex(newAuthorityIdx)
	if err != nil {
		return err
	}

	accountState, err := unmarshalUpgradeableLoaderState(account.Data())
	if err != nil {
		return err
	}

	switch accountState.Type {
	case UpgradeableLoaderStateTypeBuffer:
		{
			if accountState.Buffer.AuthorityAddress == nil {
				klog.Infof("buffer is immutable")
				return InstrErrImmutable
			}

			if *accountState.Buffer.AuthorityAddress != presentAuthorityKey {
				klog.Infof("incorrect buffer authority provided")
				return InstrErrIncorrectAuthority
			}

			isSigner, err := instrCtx.IsInstructionAccountSigner(1)
			if err != nil {
				return err
			}

			if !isSigner {
				klog.Infof("buffer authority did not sign")
				return InstrErrMissingRequiredSignature
			}

			isSigner, err = instrCtx.IsInstructionAccountSigner(2)
			if err != nil {
				return err
			}

			if !isSigner {
				klog.Infof("new authority did not sign")
				return InstrErrMissingRequiredSignature
			}

			accountState.Buffer.AuthorityAddress = &newAuthority
			err = setUpgradeableLoaderAccountState(account, accountState, execCtx.GlobalCtx.Features)
			if err != nil {
				return err
			}
		}

	case UpgradeableLoaderStateTypeProgramData:
		{
			if accountState.ProgramData.UpgradeAuthorityAddress == nil {
				klog.Infof("program not upgradeable")
				return InstrErrImmutable
			}

			if *accountState.ProgramData.UpgradeAuthorityAddress != presentAuthorityKey {
				klog.Infof("incorrect upgrade authority provided")
				return InstrErrIncorrectAuthority
			}

			isSigner, err := instrCtx.IsInstructionAccountSigner(1)
			if err != nil {
				return err
			}

			if !isSigner {
				klog.Infof("buffer authority did not sign")
				return InstrErrMissingRequiredSignature
			}

			isSigner, err = instrCtx.IsInstructionAccountSigner(2)
			if err != nil {
				return err
			}

			if !isSigner {
				klog.Infof("new authority did not sign")
				return InstrErrMissingRequiredSignature
			}

			accountState.ProgramData.UpgradeAuthorityAddress = &newAuthority
			err = setUpgradeableLoaderAccountState(account, accountState, execCtx.GlobalCtx.Features)
			if err != nil {
				return err
			}
		}

	default:
		{
			klog.Infof("account does not support authorities")
			return InstrErrInvalidArgument
		}
	}

	klog.Infof("new authority: %s", newAuthority)

	return nil
}

func closeAcctCommon(authorityAddr *solana.PublicKey, txCtx *TransactionCtx, instrCtx *InstructionCtx, f features.Features) error {
	if authorityAddr == nil {
		klog.Infof("Account is immutable")
		return InstrErrImmutable
	}

	idxInTx, err := instrCtx.IndexOfInstructionAccountInTransaction(2)
	if err != nil {
		return err
	}

	auth, err := txCtx.KeyOfAccountAtIndex(idxInTx)
	if err != nil {
		return err
	}

	if *authorityAddr != auth {
		klog.Infof("Incorrect authority provided")
		return InstrErrIncorrectAuthority
	}

	isSigner, err := instrCtx.IsInstructionAccountSigner(2)
	if err != nil {
		return err
	}

	if !isSigner {
		klog.Infof("Authority did not sign")
		return InstrErrMissingRequiredSignature
	}

	closeAcct, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}
	defer closeAcct.Drop()

	recipientAcct, err := instrCtx.BorrowInstructionAccount(txCtx, 1)
	if err != nil {
		return err
	}
	defer recipientAcct.Drop()

	err = recipientAcct.CheckedAddLamports(closeAcct.Lamports(), f)
	if err != nil {
		return err
	}

	err = closeAcct.SetLamports(0, f)
	if err != nil {
		return err
	}

	newUninitialized := &UpgradeableLoaderState{Type: UpgradeableLoaderStateTypeUninitialized}
	err = setUpgradeableLoaderAccountState(closeAcct, newUninitialized, f)

	return err
}

func UpgradeableLoaderClose(execCtx *ExecutionCtx, txCtx *TransactionCtx, instrCtx *InstructionCtx) error {
	klog.Infof("Close instr")

	err := instrCtx.CheckNumOfInstructionAccounts(2)
	if err != nil {
		return err
	}

	idx1, err1 := instrCtx.IndexOfInstructionAccountInTransaction(0)
	if err1 != nil {
		return err1
	}

	idx2, err2 := instrCtx.IndexOfInstructionAccountInTransaction(1)
	if err2 != nil {
		return err2
	}

	if idx1 == idx2 {
		klog.Infof("recipient is the same as the account being closed")
		return InstrErrInvalidArgument
	}

	closeAcct, err := instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}
	defer closeAcct.Drop()

	closeKey := closeAcct.Key()

	closeAcctState, err := unmarshalUpgradeableLoaderState(closeAcct.Data())
	if err != nil {
		return err
	}

	err = closeAcct.SetDataLength(upgradeableLoaderSizeOfUninitialized, execCtx.GlobalCtx.Features)
	if err != nil {
		return err
	}

	switch closeAcctState.Type {
	case UpgradeableLoaderStateTypeUninitialized:
		{
			recipientAcct, err := instrCtx.BorrowInstructionAccount(txCtx, 1)
			if err != nil {
				return err
			}
			defer recipientAcct.Drop()

			err = recipientAcct.CheckedAddLamports(closeAcct.Lamports(), execCtx.GlobalCtx.Features)
			if err != nil {
				return err
			}

			err = closeAcct.SetLamports(0, execCtx.GlobalCtx.Features)
			if err != nil {
				return err
			}

			klog.Infof("closed uninitialized %s", closeKey)
		}

	case UpgradeableLoaderStateTypeBuffer:
		{
			err = instrCtx.CheckNumOfInstructionAccounts(3)
			if err != nil {
				klog.Infof("(buffer) not enough instruction accounts (%d)", instrCtx.NumberOfInstructionAccounts())
				return err
			}

			closeAcct.Drop()

			err = closeAcctCommon(closeAcctState.Buffer.AuthorityAddress, txCtx, instrCtx, execCtx.GlobalCtx.Features)
			if err != nil {
				return err
			}

			klog.Infof("closed buffer %s", closeKey)
		}

	case UpgradeableLoaderStateTypeProgramData:
		{
			err = instrCtx.CheckNumOfInstructionAccounts(4)
			if err != nil {
				klog.Infof("(ProgramData) not enough instruction accounts (%d)", instrCtx.NumberOfInstructionAccounts())
				return err
			}

			closeAcct.Drop()

			programAcct, err := instrCtx.BorrowInstructionAccount(txCtx, 3)
			if err != nil {
				return err
			}
			defer programAcct.Drop()

			programKey := programAcct.Key()

			if !programAcct.IsWritable() {
				klog.Infof("program account is not writable")
				return InstrErrInvalidArgument
			}

			programId, err := instrCtx.LastProgramKey(txCtx)
			if err != nil {
				return err
			}

			if programAcct.Owner() != programId {
				klog.Infof("program account not owned by loader")
				return InstrErrIncorrectProgramId
			}

			clock, err := ReadClockSysvar(&execCtx.Accounts)
			if err != nil {
				return err
			}

			if clock.Slot == closeAcctState.ProgramData.Slot {
				klog.Infof("program was deployed in this block already")
				return InstrErrInvalidArgument
			}

			programAcctState, err := unmarshalUpgradeableLoaderState(programAcct.Data())
			if err != nil {
				return err
			}

			switch programAcctState.Type {
			case UpgradeableLoaderStateTypeProgram:
				{
					if programAcctState.Program.ProgramDataAddress != closeKey {
						klog.Infof("ProgramData account does not match ProgramData account")
						return InstrErrInvalidArgument
					}

					programAcct.Drop()

					err = closeAcctCommon(closeAcctState.ProgramData.UpgradeAuthorityAddress, txCtx, instrCtx, execCtx.GlobalCtx.Features)
					if err != nil {
						return err
					}

					/* TODO?:
						let clock = invoke_context.get_sysvar_cache().get_clock()?;
					    invoke_context.programs_modified_by_tx.replenish(
					            program_key,
					            Arc::new(LoadedProgram::new_tombstone(
					                            clock.slot,
					                            LoadedProgramType::Closed,
					            )),
					    );
					*/
				}

			default:
				{
					klog.Infof("Invalid Program account")
					return InstrErrInvalidArgument
				}
			}

			klog.Infof("Closed program %s", programKey)
		}

	default:
		{
			klog.Infof("Account does not support closing")
			return InstrErrInvalidArgument
		}
	}

	return nil
}

func UpgradeableLoaderExtendProgram(execCtx *ExecutionCtx, txCtx *TransactionCtx, instrCtx *InstructionCtx, additionalBytes uint32) error {
	klog.Infof("ExtendProgram instr")

	if additionalBytes == 0 {
		klog.Infof("Additional bytes must be greater than 0")
		return InstrErrInvalidInstructionData
	}

	programDataAcctIdx := uint64(0)
	programAcctIdx := uint64(1)
	optionalPayerAcctIdx := uint64(3)

	programDataAcct, err := instrCtx.BorrowInstructionAccount(txCtx, programDataAcctIdx)
	if err != nil {
		return err
	}
	defer programDataAcct.Drop()

	programDataKey := programDataAcct.Key()

	programId, err := instrCtx.LastProgramKey(txCtx)
	if err != nil {
		return err
	}

	if programId != programDataAcct.Owner() {
		klog.Infof("ProgramData owner is invalid")
		return InstrErrInvalidAccountOwner
	}

	if !programDataAcct.IsWritable() {
		klog.Infof("ProgramData is not writable")
		return InstrErrInvalidArgument
	}

	programAcct, err := instrCtx.BorrowInstructionAccount(txCtx, programAcctIdx)
	if err != nil {
		return err
	}
	defer programAcct.Drop()

	if !programAcct.IsWritable() {
		klog.Infof("Program account is not writable")
		return InstrErrInvalidArgument
	}

	if programAcct.Owner() != programId {
		klog.Infof("Program account is not owned by the loader")
		return InstrErrInvalidAccountOwner
	}

	//programKey := programAcct.Key()

	programAcctState, err := unmarshalUpgradeableLoaderState(programAcct.Data())
	if err != nil {
		return err
	}

	switch programAcctState.Type {
	case UpgradeableLoaderStateTypeProgram:
		{
			if programAcctState.Program.ProgramDataAddress != programDataKey {
				klog.Infof("Program account does not match ProgramData account")
				return InstrErrInvalidArgument
			}
		}
	default:
		{
			klog.Infof("Invalid Program account")
			return InstrErrInvalidAccountData
		}
	}

	programAcct.Drop()

	oldLen := uint64(len(programDataAcct.Data()))
	newLen := safemath.SaturatingAddU64(oldLen, uint64(additionalBytes))
	if newLen > MaxPermittedDataLength {
		klog.Infof("Extended ProgramData length of %d bytes exceeds max account data length of %d bytes", newLen, MaxPermittedDataLength)
		return InstrErrInvalidRealloc
	}

	clock, err := ReadClockSysvar(&execCtx.Accounts)
	if err != nil {
		return err
	}

	clockSlot := clock.Slot

	programDataAcctState, err := unmarshalUpgradeableLoaderState(programDataAcct.Data())
	if err != nil {
		return err
	}

	if programDataAcctState.Type == UpgradeableLoaderStateTypeProgramData {
		if clockSlot == programDataAcctState.ProgramData.Slot {
			klog.Infof("Program was extended in this block already")
			return InstrErrInvalidArgument
		}

		if programDataAcctState.ProgramData.UpgradeAuthorityAddress == nil {
			klog.Infof("Cannot extend ProgramData accounts that are not upgradeable")
			return InstrErrImmutable
		}
	} else {
		klog.Infof("ProgramData state is invalid")
		return InstrErrInvalidAccountData
	}

	rent, err := ReadRentSysvar(&execCtx.Accounts)
	if err != nil {
		return err
	}

	balance := programDataAcct.Lamports()
	minBalance := rent.MinimumBalance(newLen)
	if minBalance > 1 {
		minBalance = 1
	}
	requiredPayment := safemath.SaturatingSubU64(minBalance, balance)

	programDataAcct.Drop()

	if requiredPayment > 0 {
		payerKeyIdx, err := instrCtx.IndexOfInstructionAccountInTransaction(optionalPayerAcctIdx)
		if err != nil {
			return err
		}
		payerKey, err := txCtx.KeyOfAccountAtIndex(payerKeyIdx)
		if err != nil {
			return err
		}

		txInstr := newTransferInstruction(payerKey, programDataKey, requiredPayment)
		err = execCtx.NativeInvoke(*txInstr, nil)
		if err != nil {
			return err
		}
	}

	programDataAcct, err = instrCtx.BorrowInstructionAccount(txCtx, programDataAcctIdx)
	if err != nil {
		return err
	}

	err = programDataAcct.SetDataLength(newLen, execCtx.GlobalCtx.Features)
	if err != nil {
		return err
	}

	programBytes := programDataAcct.Data()
	if uint64(len(programBytes)) < upgradeableLoaderSizeOfProgramDataMetaData {
		return InstrErrAccountDataTooSmall
	}
	err = deployProgram(execCtx, programBytes[upgradeableLoaderSizeOfProgramDataMetaData:])
	if err != nil {
		klog.Infof("deploy program failed")
		return InstrErrInvalidAccountData
	}

	programDataAcctState.ProgramData.Slot = clockSlot
	err = setUpgradeableLoaderAccountState(programDataAcct, programDataAcctState, execCtx.GlobalCtx.Features)
	if err != nil {
		return err
	}

	klog.Infof("Extended ProgramData account by %d bytes", additionalBytes)

	return nil
}

func ProcessUpgradeableLoaderInstruction(execCtx *ExecutionCtx) error {
	klog.Infof("BPF loader program mgmt")

	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	instrData := instrCtx.Data

	_, err = instrCtx.LastProgramKey(txCtx)
	if err != nil {
		return err
	}

	decoder := bin.NewBinDecoder(instrData)

	instrType, err := decoder.ReadUint32(bin.LE)
	if err != nil {
		return InstrErrInvalidInstructionData
	}

	switch instrType {
	case UpgradeableLoaderInstrTypeInitializeBuffer:
		{
			err = UpgradeableLoaderInitializeBuffer(execCtx, txCtx, instrCtx)
		}

	case UpgradeableLoaderInstrTypeWrite:
		{
			var write UpgradeableLoaderInstrWrite
			err = write.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}

			err = UpgradeableLoaderWrite(execCtx, txCtx, instrCtx, write)
		}

	case UpgradeableLoaderInstrTypeDeployWithMaxDataLen:
		{
			var deploy UpgradeableLoaderInstrDeployWithMaxDataLen
			err = deploy.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}

			err = UpgradeableLoaderDeployWithMaxDataLen(execCtx, txCtx, instrCtx, deploy)
		}

	case UpgradeableLoaderInstrTypeUpgrade:
		{
			err = UpgradeableLoaderUpgrade(execCtx, txCtx, instrCtx)
		}

	case UpgradeableLoaderInstrTypeSetAuthority:
		{
			err = UpgradeableLoaderSetAuthority(execCtx, txCtx, instrCtx)
		}

	case UpgradeableLoaderInstrTypeSetAuthorityChecked:
		{
			err = UpgradeableLoaderSetAuthorityChecked(execCtx, txCtx, instrCtx)
		}

	case UpgradeableLoaderInstrTypeClose:
		{
			err = UpgradeableLoaderClose(execCtx, txCtx, instrCtx)
		}

	case UpgradeableLoaderInstrTypeExtendProgram:
		{
			var extend UpgradeableLoaderInstrExtendProgram
			err = extend.UnmarshalWithDecoder(decoder)
			if err != nil {
				return InstrErrInvalidInstructionData
			}

			err = UpgradeableLoaderExtendProgram(execCtx, txCtx, instrCtx, extend.AdditionalBytes)
		}
	default:
		{
			err = InstrErrInvalidInstructionData
		}
	}

	return err
}
