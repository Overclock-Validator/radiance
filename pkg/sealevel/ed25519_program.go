package sealevel

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"go.firedancer.io/radiance/pkg/features"
)

const DataStart = (SignatureOffsetsSerializedSize + SignatureOffsetStarts)
const SignatureOffsetStarts = 2
const SignatureOffsetsSerializedSize = 14

const SignatureSerializedSize = 64
const PubkeySerializedSize = 32

type Ed25519SignatureOffsets struct {
	SignatureOffset           uint16
	SignatureInstructionIndex uint16
	PublicKeyOffset           uint16
	PublicKeyInstructionIndex uint16
	MessageDataOffset         uint16
	MessageDataSize           uint16
	MessageInstructionIndex   uint16
}

func (offsets *Ed25519SignatureOffsets) UnmarshalWithDecoder(buf io.Reader) error {
	err := binary.Read(buf, binary.LittleEndian, &offsets.SignatureOffset)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &offsets.SignatureInstructionIndex)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &offsets.PublicKeyOffset)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &offsets.PublicKeyInstructionIndex)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &offsets.MessageDataOffset)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &offsets.MessageDataSize)
	if err != nil {
		return err
	}

	err = binary.Read(buf, binary.LittleEndian, &offsets.MessageInstructionIndex)
	if err != nil {
		return err
	}

	return nil
}

func ed25519GetDataSlice(txCtx *TransactionCtx, index uint16, offset uint16, size uint16) ([]byte, error) {

	var data []byte
	var dataSize uint64

	// data from current instruction
	if index == math.MaxUint16 {
		instrCtx, _ := txCtx.CurrentInstructionCtx()
		data = instrCtx.Data
		dataSize = uint64(len(data))
	} else {
		if int(index) >= len(txCtx.AllInstructions) {
			return nil, PrecompileErrDataOffset
		}
		data = txCtx.AllInstructions[index].Data
		dataSize = uint64(len(data))
	}

	if uint64(offset)+uint64(size) > dataSize {
		return nil, PrecompileErrSignature
	}

	return data[offset : offset+size], nil
}

func Ed25519ProgramExecute(execCtx *ExecutionCtx) error {

	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	data := instrCtx.Data
	dataLen := uint64(len(data))

	if dataLen < DataStart {
		if dataLen == 2 && data[0] == 0 {
			return nil
		}
		return PrecompileErrInstrDataSize
	}

	numSignatures := data[0]

	if numSignatures == 0 {
		return PrecompileErrInstrDataSize
	}

	expectedDataSize := (uint64(numSignatures) * SignatureOffsetsSerializedSize) + SignatureOffsetStarts
	if dataLen < expectedDataSize {
		return PrecompileErrInstrDataSize
	}

	off := SignatureOffsetStarts
	for count := uint64(0); count < uint64(numSignatures); count++ {
		var offsets Ed25519SignatureOffsets
		err := offsets.UnmarshalWithDecoder(bytes.NewReader(data[off:]))
		if err != nil {
			panic("shouldn't happen")
		}

		off += SignatureOffsetsSerializedSize

		signature, err := ed25519GetDataSlice(txCtx, offsets.SignatureInstructionIndex, offsets.SignatureOffset, SignatureSerializedSize)
		if err != nil {
			return PrecompileErrDataOffset
		}

		pubkey, err := ed25519GetDataSlice(txCtx, offsets.PublicKeyInstructionIndex, offsets.PublicKeyOffset, PubkeySerializedSize)
		if err != nil {
			return PrecompileErrDataOffset
		}

		msg, err := ed25519GetDataSlice(txCtx, offsets.MessageInstructionIndex, offsets.MessageDataOffset, offsets.MessageDataSize)
		if err != nil {
			return PrecompileErrDataOffset
		}

		pk := ed25519.PublicKey(pubkey)

		if execCtx.GlobalCtx.Features.IsActive(features.Ed25519PrecompileVerifyStrict) {
			verifyOptions := ed25519.VerifyOptions{AllowSmallOrderA: false, AllowSmallOrderR: false, CofactorlessVerify: true}
			opts := ed25519.Options{Verify: &verifyOptions}

			if !ed25519.VerifyWithOptions(pk, msg[:offsets.MessageDataSize], signature[:64], &opts) {
				return PrecompileErrSignature
			}
		} else {
			if !ed25519.Verify(pk, msg[:offsets.MessageDataSize], signature[:64]) {
				return PrecompileErrSignature
			}
		}
	}

	return nil
}
