package sealevel

import (
	"fmt"

	"github.com/Overclock-Validator/mithril/pkg/safemath"
	bin "github.com/gagliardetto/binary"
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

func (requestHeapFrame *ComputeBudgetInstrRequestHeapFrame) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint8(ComputeBudgetInstrTypeRequestHeapFrame)
	if err != nil {
		return err
	}

	err = encoder.WriteUint32(requestHeapFrame.Bytes, bin.LE)
	return err
}

func (setComputeUnitLimit *ComputeBudgetInstrSetComputeUnitLimit) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	setComputeUnitLimit.ComputeUnitLimit, err = decoder.ReadUint32(bin.LE)
	return err
}

func (setComputeUnitLimit *ComputeBudgetInstrSetComputeUnitLimit) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint8(ComputeBudgetInstrTypeSetComputeUnitLimit)
	if err != nil {
		return err
	}

	err = encoder.WriteUint32(setComputeUnitLimit.ComputeUnitLimit, bin.LE)
	return err
}

func (setComputeUnitPrice *ComputeBudgetInstrSetComputeUnitPrice) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	setComputeUnitPrice.MicroLamports, err = decoder.ReadUint64(bin.LE)
	return err
}

func (setComputeUnitPrice *ComputeBudgetInstrSetComputeUnitPrice) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint8(ComputeBudgetInstrTypeSetComputeUnitPrice)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(setComputeUnitPrice.MicroLamports, bin.LE)
	return err
}

func (setLoadedAccountsDataSizeLimit *ComputeBudgetInstrSetLoadedAccountsDataSizeLimit) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	var err error
	setLoadedAccountsDataSizeLimit.Bytes, err = decoder.ReadUint32(bin.LE)
	return err
}

func (setLoadedAccountsDataSizeLimit *ComputeBudgetInstrSetLoadedAccountsDataSizeLimit) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint8(ComputeBudgetInstrTypeSetLoadedAccountsDataSizeLimit)
	if err != nil {
		return err
	}

	err = encoder.WriteUint32(setLoadedAccountsDataSizeLimit.Bytes, bin.LE)
	return err
}

func sanitizeRequestedHeapSize(len uint32) bool {
	return len >= MinHeapFrameBytes && len <= MaxHeapFrameBytes && (len%HeapFrameBytesMultiple == 0)
}

func invalidInstructionDataErr(idx int) error {
	return fmt.Errorf("Error processing Instruction %d: %w", idx, InstrErrInvalidInstructionData)
}

func duplicateInstructionErr(idx int) error {
	return fmt.Errorf("Transaction contains a duplicate instruction (%d) that is not allowed", idx)
}

func ComputeBudgetExecuteInstructions(instructions []Instruction) (*ComputeBudgetLimits, error) {
	var hasRequestedHeapSize bool
	var hasComputeUnitLimit bool
	var hasComputeUnitPrice bool
	var hasUpdatedLoadedAccountsDataSizeLimit bool

	var numNonComputeBudgetInstrs uint32
	var requestedHeapSize uint32
	var updatedComputeUnitLimit uint32
	var updatedLoadedAccountsDataSizeLimit uint32
	var updatedComputeUnitPrice uint64

	for idx, instr := range instructions {
		if instr.ProgramId != ComputeBudgetProgramAddr {
			numNonComputeBudgetInstrs++
			continue
		}

		instrData := instr.Data
		decoder := bin.NewBorshDecoder(instrData)

		instrType, err := decoder.ReadUint8()
		if err != nil {
			return nil, invalidInstructionDataErr(idx)
		}

		switch instrType {
		case ComputeBudgetInstrTypeRequestHeapFrame:
			{
				var requestHeapFrame ComputeBudgetInstrRequestHeapFrame
				err = requestHeapFrame.UnmarshalWithDecoder(decoder)
				if err != nil {
					return nil, invalidInstructionDataErr(idx)
				}

				if hasRequestedHeapSize {
					return nil, duplicateInstructionErr(idx)
				}

				requestedSize := requestHeapFrame.Bytes

				if sanitizeRequestedHeapSize(requestedSize) {
					requestedHeapSize = requestedSize
					hasRequestedHeapSize = true
				} else {
					return nil, invalidInstructionDataErr(idx)
				}
			}

		case ComputeBudgetInstrTypeSetComputeUnitLimit:
			{
				var setComputeUnitLimit ComputeBudgetInstrSetComputeUnitLimit
				err = setComputeUnitLimit.UnmarshalWithDecoder(decoder)
				if err != nil {
					return nil, invalidInstructionDataErr(idx)
				}

				if hasComputeUnitLimit {
					return nil, duplicateInstructionErr(idx)
				}

				updatedComputeUnitLimit = setComputeUnitLimit.ComputeUnitLimit
				hasComputeUnitLimit = true
			}

		case ComputeBudgetInstrTypeSetComputeUnitPrice:
			{
				var setComputeUnitPrice ComputeBudgetInstrSetComputeUnitPrice
				err = setComputeUnitPrice.UnmarshalWithDecoder(decoder)
				if err != nil {
					return nil, invalidInstructionDataErr(idx)
				}

				if hasComputeUnitPrice {
					return nil, duplicateInstructionErr(idx)
				}

				updatedComputeUnitPrice = setComputeUnitPrice.MicroLamports
				hasComputeUnitPrice = true
			}

		case ComputeBudgetInstrTypeSetLoadedAccountsDataSizeLimit:
			{
				var setLoadedAccountsDataSizeLimit ComputeBudgetInstrSetLoadedAccountsDataSizeLimit
				err = setLoadedAccountsDataSizeLimit.UnmarshalWithDecoder(decoder)
				if err != nil {
					return nil, invalidInstructionDataErr(idx)
				}

				if hasUpdatedLoadedAccountsDataSizeLimit {
					return nil, duplicateInstructionErr(idx)
				}

				updatedLoadedAccountsDataSizeLimit = setLoadedAccountsDataSizeLimit.Bytes
				hasUpdatedLoadedAccountsDataSizeLimit = true
			}

		default:
			{
				return nil, invalidInstructionDataErr(idx)
			}
		}
	}

	var updatedHeapBytes uint32
	if hasRequestedHeapSize {
		updatedHeapBytes = requestedHeapSize
	} else {
		updatedHeapBytes = MinHeapFrameBytes
	}
	if updatedHeapBytes > MaxHeapFrameBytes {
		updatedHeapBytes = MaxHeapFrameBytes
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
