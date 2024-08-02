package sealevel

import (
	"bytes"
	"errors"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	bin "github.com/gagliardetto/binary"
	"go.firedancer.io/radiance/pkg/features"
	"golang.org/x/crypto/sha3"
)

const Secp256k1SignatureOffsetsSerializedSize = 11
const Secp256k1SignatureSerializedSize = 64
const Secp256k1HashedPubkeySerializedSize = 20
const Secp256k1SignatureOffsetsStart = 1
const Secp256k1DataStart = (Secp256k1SignatureOffsetsSerializedSize + Secp256k1SignatureOffsetsStart)

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

func Secp256k1ProgramExecute(execCtx *ExecutionCtx) error {

	txCtx := execCtx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	data := instrCtx.Data
	dataLen := uint64(len(data))

	if dataLen < Secp256k1DataStart {
		if dataLen == 1 && data[0] == 0 {
			return nil
		}
		return PrecompileErrInstrDataSize
	}

	numSignatures := data[0]

	if (execCtx.GlobalCtx.Features.IsActive(features.Libsecp256k1FailOnBadCount) ||
		execCtx.GlobalCtx.Features.IsActive(features.Libsecp256k1FailOnBadCount2)) && numSignatures == 0 && dataLen > 1 {
		return PrecompileErrInstrDataSize
	}

	expectedDataSize := (uint64(numSignatures) * Secp256k1SignatureOffsetsSerializedSize) + Secp256k1SignatureOffsetsStart
	if dataLen < expectedDataSize {
		return PrecompileErrInstrDataSize
	}

	dec := bin.NewBinDecoder(data[Secp256k1SignatureOffsetsStart:])

	for count := uint64(0); count < uint64(numSignatures); count++ {
		var secpOffsets SecppSignatureOffsets
		err := secpOffsets.UnmarshalWithDecoder(dec)
		if err != nil {
			panic("shouldn't happen, lengths already checked")
		}

		signature, err := PrecompileGetDataSlice(txCtx, uint16(secpOffsets.SignatureInstructionIndex), secpOffsets.SignatureOffset, SignatureSerializedSize+1)
		if err != nil {
			return PrecompileErrDataOffset
		}

		ethAddr, err := PrecompileGetDataSlice(txCtx, uint16(secpOffsets.EthAddressInstructionIndex), secpOffsets.EthAddressOffset, Secp256k1HashedPubkeySerializedSize)
		if err != nil {
			return PrecompileErrDataOffset
		}

		msg, err := PrecompileGetDataSlice(txCtx, uint16(secpOffsets.MessageInstructionIndex), secpOffsets.MessageDataOffset, secpOffsets.MessageDataSize)
		if err != nil {
			return PrecompileErrDataOffset
		}

		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(msg)
		messageHash := hasher.Sum(nil)

		recoveredPubkeyBytes, err := secp256k1.RecoverPubkey(messageHash, signature)
		if err != nil {
			return PrecompileErrSignature
		}

		hasher.Reset()
		hasher.Write(recoveredPubkeyBytes[1:])
		digest := hasher.Sum(nil)[sha3.NewLegacyKeccak256().Size()-Secp256k1HashedPubkeySerializedSize:] // 12

		if !bytes.Equal(ethAddr, digest) {
			return PrecompileErrSignature
		}
	}

	return nil
}
