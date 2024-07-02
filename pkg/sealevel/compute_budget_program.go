package sealevel

import (
	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/safemath"
	"k8s.io/klog/v2"
)

const (
	MinHeapFrameBytes                  = (32 * 1024)
	MaxHeapFrameBytes                  = (256 * 1024)
	HeapFrameBytesMultiple             = 1024
	DefaultInstructionComputeUnitLimit = 200000
	MaxComputeUnitLimit                = 1400000
	MaxLoadedAccountsDataSizeBytes     = (64 * 1024 * 1024)
)

type ComputeBudgetLimits struct {
	UpdatedHeapBytes   uint32
	ComputeUnitLimit   uint32
	ComputeUnitPrice   uint64
	LoadedAccountBytes uint32
}

const (
	ComputeBudgetInstrTypeRequestHeapFrame               = 1
	ComputeBudgetInstrTypeSetComputeUnitLimit            = 2
	ComputeBudgetInstrTypeSetComputeUnitPrice            = 3
	ComputeBudgetInstrTypeSetLoadedAccountsDataSizeLimit = 4
)

type ComputeBudgetInstrRequestHeapFrame struct {
	Bytes uint32
}

type ComputeBudgetInstrSetComputeUnitLimit struct {
	ComputeUnitLimit uint32
}

type ComputeBudgetInstrSetComputeUnitPrice struct {
	MicroLamports uint64
}

type ComputeBudgetInstrSetLoadedAccountsDataSizeLimit struct {
	Bytes uint32
}

func (requestHeapFrame *ComputeBudgetInstrRequestHeapFrame) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	requestHeapFrame.Bytes, err = decoder.ReadUint32(bin.LE)
	return err
}

func (setComputeUnitLimit *ComputeBudgetInstrSetComputeUnitLimit) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	setComputeUnitLimit.ComputeUnitLimit, err = decoder.ReadUint32(bin.LE)
	return err
}

func (setComputeUnitPrice *ComputeBudgetInstrSetComputeUnitPrice) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	setComputeUnitPrice.MicroLamports, err = decoder.ReadUint64(bin.LE)
	return err
}

func (setLoadedAccountsDataSizeLimit *ComputeBudgetInstrSetLoadedAccountsDataSizeLimit) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	setLoadedAccountsDataSizeLimit.Bytes, err = decoder.ReadUint32(bin.LE)
	return err
}

func sanitizeRequestedHeapSize(len uint32) bool {
	return len >= MinHeapFrameBytes && len <= MaxHeapFrameBytes && (len%HeapFrameBytesMultiple == 0)
}

func ComputeBudgetExecuteInstructions(execCtx *ExecutionCtx, instructions []Instruction) (*ComputeBudgetLimits, error) {

	var hasRequestedHeapSize bool
	var hasComputeUnitLimit bool
	var hasComputeUnitPrice bool
	var hasUpdatedLoadedAccountsDataSizeLimit bool

	var numNonComputeBudgetInstrs uint32
	var requestedHeapSize uint32
	var updatedComputeUnitLimit uint32
	var updatedLoadedAccountsDataSizeLimit uint32
	var updatedComputeUnitPrice uint64

	for _, instr := range instructions {
		if instr.ProgramId != ComputeBudgetProgramAddr {
			numNonComputeBudgetInstrs++
			continue
		}

		instrData := instr.Data
		decoder := bin.NewBorshDecoder(instrData)

		instrType, err := decoder.ReadUint32(bin.LE)
		if err != nil {
			return nil, InstrErrInvalidInstructionData
		}

		switch instrType {
		case ComputeBudgetInstrTypeRequestHeapFrame:
			{
				var requestHeapFrame ComputeBudgetInstrRequestHeapFrame
				err = requestHeapFrame.UnmarshalWithDecoder(decoder)
				if err != nil {
					return nil, InstrErrInvalidInstructionData
				}

				if hasRequestedHeapSize {
					// TODO: seems to be the wrong error to return
					return nil, InstrErrInvalidInstructionData
				}

				requestedSize := requestHeapFrame.Bytes

				if sanitizeRequestedHeapSize(requestedSize) {
					hasRequestedHeapSize = true
					requestedHeapSize = requestedSize
				} else {
					return nil, InstrErrInvalidInstructionData
				}
			}

		case ComputeBudgetInstrTypeSetComputeUnitLimit:
			{
				var setComputeUnitLimit ComputeBudgetInstrSetComputeUnitLimit
				err = setComputeUnitLimit.UnmarshalWithDecoder(decoder)
				if err != nil {
					return nil, InstrErrInvalidInstructionData
				}

				if hasComputeUnitLimit {
					// TODO: seems to be the wrong error to return
					return nil, InstrErrInvalidInstructionData
				}

				updatedComputeUnitLimit = setComputeUnitLimit.ComputeUnitLimit
			}

		case ComputeBudgetInstrTypeSetComputeUnitPrice:
			{
				var setComputeUnitPrice ComputeBudgetInstrSetComputeUnitPrice
				err = setComputeUnitPrice.UnmarshalWithDecoder(decoder)
				if err != nil {
					return nil, InstrErrInvalidInstructionData
				}

				if hasComputeUnitPrice {
					// TODO: seems to be the wrong error to return
					return nil, InstrErrInvalidInstructionData
				}

				updatedComputeUnitPrice = setComputeUnitPrice.MicroLamports
			}

		case ComputeBudgetInstrTypeSetLoadedAccountsDataSizeLimit:
			{
				var setLoadedAccountsDataSizeLimit ComputeBudgetInstrSetLoadedAccountsDataSizeLimit
				err = setLoadedAccountsDataSizeLimit.UnmarshalWithDecoder(decoder)
				if err != nil {
					return nil, InstrErrInvalidInstructionData
				}

				if hasUpdatedLoadedAccountsDataSizeLimit {
					// TODO: seems to be the wrong error to return
					return nil, InstrErrInvalidInstructionData
				}

				updatedLoadedAccountsDataSizeLimit = setLoadedAccountsDataSizeLimit.Bytes
			}

		default:
			{
				return nil, InstrErrInvalidInstructionData
			}
		}
	}

	var updatedHeapBytes uint32
	if hasRequestedHeapSize {
		updatedHeapBytes = requestedHeapSize
	} else {
		updatedHeapBytes = MinHeapFrameBytes
	}

	var computeUnitLimit uint32
	if hasComputeUnitLimit {
		if updatedComputeUnitLimit < MaxComputeUnitLimit {
			computeUnitLimit = updatedComputeUnitLimit
		} else {
			computeUnitLimit = MaxComputeUnitLimit
		}
	} else {
		computeUnitLimit = safemath.SaturatingMulU32(numNonComputeBudgetInstrs, DefaultInstructionComputeUnitLimit)
		if computeUnitLimit > MaxComputeUnitLimit {
			computeUnitLimit = MaxComputeUnitLimit
		}
	}

	var computeUnitPrice uint64
	if hasComputeUnitPrice {
		computeUnitPrice = updatedComputeUnitPrice
	}

	var loadedAccountBytes uint32
	if hasUpdatedLoadedAccountsDataSizeLimit {
		if updatedLoadedAccountsDataSizeLimit < MaxLoadedAccountsDataSizeBytes {
			loadedAccountBytes = updatedLoadedAccountsDataSizeLimit
		} else {
			loadedAccountBytes = MaxLoadedAccountsDataSizeBytes
		}
	} else {
		loadedAccountBytes = MaxLoadedAccountsDataSizeBytes
	}

	computeBudgetLimits := &ComputeBudgetLimits{UpdatedHeapBytes: updatedHeapBytes,
		ComputeUnitLimit: computeUnitLimit, ComputeUnitPrice: computeUnitPrice, LoadedAccountBytes: loadedAccountBytes}

	return computeBudgetLimits, nil
}

func ComputeBudgetExecute(execCtx *ExecutionCtx) error {
	klog.Infof("ComputeBudget program")
	err := execCtx.ComputeMeter.Consume(CUComputeBudgetProgramDefaultComputeUnits)
	return err
}
