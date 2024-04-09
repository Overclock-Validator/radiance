package sealevel

import (
	"bytes"
	"errors"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/features"
	"golang.org/x/crypto/sha3"
	"k8s.io/klog/v2"
)

const Secp256k1SignatureOffsetsSerializedSize = 11
const Secp256k1SignatureSerializedSize = 64
const Secp256k1HashedPubkeySerializedSize = 20

type SecppSignatureOffsets struct {
	SignatureOffset            uint16
	SignatureInstructionIndex  byte
	EthAddressOffset           uint16
	EthAddressInstructionIndex byte
	MessageDataOffset          uint16
	MessageDataSize            uint16
	MessageInstructionIndex    byte
}

func (so *SecppSignatureOffsets) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {
	so.SignatureOffset, err = decoder.ReadUint16(bin.LE)
	if err != nil {
		return
	}

	so.SignatureInstructionIndex, err = decoder.ReadByte()
	if err != nil {
		return
	}

	so.EthAddressOffset, err = decoder.ReadUint16(bin.LE)
	if err != nil {
		return
	}

	so.EthAddressInstructionIndex, err = decoder.ReadByte()
	if err != nil {
		return
	}

	so.MessageDataOffset, err = decoder.ReadUint16(bin.LE)
	if err != nil {
		return
	}

	so.MessageDataSize, err = decoder.ReadUint16(bin.LE)
	if err != nil {
		return
	}

	so.MessageInstructionIndex, err = decoder.ReadByte()
	if err != nil {
		return
	}

	return
}

var SECP256K1_N = [8]uint32{0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}

// TODO: validate that this is actually correct
func isSignatureOverflowing(b32 []byte) bool {
	bytes := make([]uint32, 8)

	bytes[0] = (uint32(b32[31])) | ((uint32(b32[30])) << 8) | ((uint32(b32[29])) << 16) |
		((uint32(b32[28])) << 24)

	bytes[1] = (uint32(b32[27])) | ((uint32(b32[26])) << 8) | ((uint32(b32[25])) << 16) |
		((uint32(b32[24])) << 24)

	bytes[2] = (uint32(b32[23])) | ((uint32(b32[22])) << 8) | ((uint32(b32[21])) << 16) |
		((uint32(b32[20])) << 24)

	bytes[3] = (uint32(b32[19])) | ((uint32(b32[18])) << 8) | ((uint32(b32[17])) << 16) |
		((uint32(b32[16])) << 24)

	bytes[4] = (uint32(b32[15])) | ((uint32(b32[14])) << 8) | ((uint32(b32[13])) << 16) |
		((uint32(b32[12])) << 24)

	bytes[5] = (uint32(b32[11])) | ((uint32(b32[10])) << 8) | ((uint32(b32[9])) << 16) |
		((uint32(b32[8])) << 24)

	bytes[6] = (uint32(b32[7])) | ((uint32(b32[6])) << 8) | ((uint32(b32[5])) << 16) |
		((uint32(b32[4])) << 24)

	bytes[7] = (uint32(b32[3])) | ((uint32(b32[2])) << 8) | ((uint32(b32[1])) << 16) |
		((uint32(b32[0])) << 24)

	var yes bool
	var no bool
	no = no || (uint32(bytes[7]) < SECP256K1_N[7])
	no = no || (uint32(bytes[6]) < SECP256K1_N[6])
	no = no || (uint32(bytes[5]) < SECP256K1_N[5])
	no = no || (uint32(bytes[4]) < SECP256K1_N[4])
	yes = yes || ((uint32(bytes[4]) > SECP256K1_N[4]) && !no)
	no = no || ((uint32(bytes[3]) < SECP256K1_N[3]) && !yes)
	yes = yes || ((uint32(bytes[3]) > SECP256K1_N[3]) && !no)
	no = no || ((uint32(bytes[2]) < SECP256K1_N[2]) && !yes)
	yes = yes || ((uint32(bytes[2]) > SECP256K1_N[2]) && !no)
	no = no || ((uint32(bytes[1]) < SECP256K1_N[1]) && !yes)
	yes = yes || ((uint32(bytes[1]) > SECP256K1_N[1]) && !no)
	yes = yes || ((uint32(bytes[0]) >= SECP256K1_N[0]) && !no)

	return yes
}

func parseAndValidateSignature(sigBytes []byte) error {
	if len(sigBytes) != Secp256k1SignatureSerializedSize {
		return errors.New("invalid signature size")
	}

	if isSignatureOverflowing(sigBytes[0:32]) || isSignatureOverflowing(sigBytes[32:]) {
		return errors.New("overflowing signature")
	}

	return nil
}

func secp256k1GetDataSlice(instructionDatas [][]byte, instructionIndex byte, offsetStart uint16, size uint64) ([]byte, int) {
	signatureIndex := uint64(instructionIndex)
	if signatureIndex >= uint64(len(instructionDatas)) {
		return nil, PrecompileErrInvalidDataOffsets
	}

	signatureInstruction := instructionDatas[signatureIndex]
	start := uint64(offsetStart)
	end := start + size
	if end > uint64(len(signatureInstruction)) {
		return nil, PrecompileErrInvalidSignature
	}

	return signatureInstruction[start:end], InstrSuccess
}

func constructEthPubkey(pubkey []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(pubkey)
	digest := hasher.Sum(nil)[12:]
	return digest
}

func Secp256k1ProgramExecute(data []byte, instructionDatas [][]byte, f features.Features) int {
	if len(data) == 0 {
		return PrecompileErrInvalidInstructionDataSize
	}

	count := uint64(data[0])

	if (f.IsActive(features.Libsecp256k1FailOnBadCount) ||
		f.IsActive(features.Libsecp256k1FailOnBadCount2)) &&
		count == 0 && len(data) > 1 {
		return PrecompileErrInvalidInstructionDataSize
	}

	expectedDataSize := (count * Secp256k1SignatureOffsetsSerializedSize) + 1
	if uint64(len(data)) < expectedDataSize {
		return PrecompileErrInvalidInstructionDataSize
	}

	for i := uint64(0); i < count; i++ {

		start := (i * Secp256k1SignatureOffsetsSerializedSize) + 1
		end := start + Secp256k1SignatureOffsetsSerializedSize

		var secpOffsets SecppSignatureOffsets
		dec := bin.NewBinDecoder(data[start:end])
		err := secpOffsets.UnmarshalWithDecoder(dec)
		if err != nil {
			return PrecompileErrInvalidSignature
		}

		signatureIndex := uint64(secpOffsets.SignatureInstructionIndex)
		if signatureIndex >= uint64(len(instructionDatas)) {
			return PrecompileErrInvalidInstructionDataSize
		}

		signatureInstruction := instructionDatas[signatureIndex]
		sigStart := uint64(secpOffsets.SignatureOffset)
		sigEnd := sigStart + Secp256k1SignatureSerializedSize
		if sigEnd >= uint64(len(signatureInstruction)) {
			return PrecompileErrInvalidSignature
		}

		signature := signatureInstruction[sigStart:sigEnd]
		err = parseAndValidateSignature(signature)
		if err != nil {
			klog.Errorf("error parsing signature: %s\n", err)
			return PrecompileErrInvalidSignature
		}

		recoveryId := signatureInstruction[sigEnd]
		if recoveryId >= 4 {
			return PrecompileErrInvalidRecoveryId
		}

		ethAddressSlice, errCode := secp256k1GetDataSlice(instructionDatas, secpOffsets.EthAddressInstructionIndex, secpOffsets.EthAddressOffset, Secp256k1HashedPubkeySerializedSize)
		if errCode != InstrSuccess {
			return errCode
		}

		messageSlice, errCode := secp256k1GetDataSlice(instructionDatas, secpOffsets.MessageInstructionIndex, secpOffsets.MessageDataOffset, uint64(secpOffsets.MessageDataSize))
		if errCode != InstrSuccess {
			return errCode
		}

		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(messageSlice)
		messageHash := hasher.Sum(nil)

		sigAndRecoveryId := make([]byte, 65)
		copy(sigAndRecoveryId, signature)
		sigAndRecoveryId[64] = byte(recoveryId)

		recoveredPubKey, err := secp256k1.RecoverPubkey(messageHash, sigAndRecoveryId)
		if err != nil {
			return PrecompileErrInvalidSignature
		}
		ethAddress := constructEthPubkey(recoveredPubKey)

		if !bytes.Equal(ethAddressSlice, ethAddress) {
			return PrecompileErrInvalidSignature
		}
	}

	return InstrSuccess
}
