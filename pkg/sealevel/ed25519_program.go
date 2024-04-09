package sealevel

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"io"
	"math"

	"go.firedancer.io/radiance/pkg/safemath"
)

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

func ed25519GetDataSlice(data []byte, instructionDatas [][]byte, instructionIndex, offsetStart uint16, size uint64) ([]byte, int) {

	var instruction []byte
	if instructionIndex == math.MaxUint16 {
		instruction = data
	} else {
		signatureIndex := int(instructionIndex)
		if signatureIndex >= len(instructionDatas) {
			return nil, PrecompileErrInvalidDataOffsets
		}
		instruction = instructionDatas[signatureIndex]
	}

	start := uint64(offsetStart)
	end := safemath.SaturatingAddU64(start, size)
	if end > uint64(len(instruction)) {
		return nil, PrecompileErrInvalidDataOffsets
	}
	return instruction[start:end], InstrSuccess
}

func Ed25519ProgramExecute(data []byte, instructionDatas [][]byte) int {
	dataLen := uint64(len(data))

	if dataLen < SignatureOffsetStarts {
		return PrecompileErrInvalidInstructionDataSize
	}

	numSignatures := data[0]

	if numSignatures == 0 && dataLen > SignatureOffsetStarts {
		return PrecompileErrInvalidInstructionDataSize
	}

	expectedDataSize := (uint64(numSignatures) * SignatureOffsetsSerializedSize) + SignatureOffsetStarts
	if dataLen < expectedDataSize {
		return PrecompileErrInvalidInstructionDataSize
	}

	for count := uint64(0); count < uint64(numSignatures); count++ {

		start := (count * SignatureOffsetsSerializedSize) + SignatureOffsetStarts
		end := start + SignatureOffsetsSerializedSize

		var offsets Ed25519SignatureOffsets
		err := offsets.UnmarshalWithDecoder(bytes.NewReader(data[start:end]))
		if err != nil {
			return PrecompileErrInvalidDataOffsets
		}

		signature, errCode := ed25519GetDataSlice(data, instructionDatas, offsets.SignatureInstructionIndex, offsets.SignatureOffset, SignatureSerializedSize)
		if errCode != InstrSuccess {
			return errCode
		}

		pubkey, errCode := ed25519GetDataSlice(data, instructionDatas, offsets.PublicKeyInstructionIndex, offsets.PublicKeyOffset, PubkeySerializedSize)
		if errCode != InstrSuccess {
			return errCode
		}

		msg, errCode := ed25519GetDataSlice(data, instructionDatas, offsets.MessageInstructionIndex, offsets.MessageDataOffset, uint64(offsets.MessageDataSize))
		if errCode != InstrSuccess {
			return errCode
		}

		if !ed25519.Verify(pubkey, msg, signature) {
			return PrecompileErrInvalidSignature
		}
	}

	return InstrSuccess
}
