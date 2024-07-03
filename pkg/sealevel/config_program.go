package sealevel

import (
	"bytes"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"k8s.io/klog/v2"
)

type ConfigKey struct {
	Pubkey   solana.PublicKey
	IsSigner bool
}

func (configKey *ConfigKey) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	pubKey, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(configKey.Pubkey[:], pubKey)

	configKey.IsSigner, err = decoder.ReadBool()
	return err
}

func (configKey *ConfigKey) MarshalWithEncoder(encoder *bin.Encoder) error {
	err := encoder.WriteBytes(configKey.Pubkey.Bytes(), false)
	if err != nil {
		return err
	}
	err = encoder.WriteBool(configKey.IsSigner)
	return err
}

func unmarshalConfigKeys(data []byte, checkMaxLen bool) ([]ConfigKey, error) {
	dec := bin.NewBinDecoder(data)

	numKeys, err := dec.ReadCompactU16()
	if err != nil {
		return nil, err
	}

	var configKeys []ConfigKey

	for i := 0; i < numKeys; i++ {
		var ck ConfigKey
		err = ck.UnmarshalWithDecoder(dec)
		if err != nil {
			return nil, err
		}
		configKeys = append(configKeys, ck)
	}

	if checkMaxLen && dec.Position() > 1232 {
		return nil, SyscallErrTooManyBytesConsumed
	}

	return configKeys, nil
}

func marshalConfigKeys(configKeys []ConfigKey) []byte {
	writer := new(bytes.Buffer)
	enc := bin.NewBinEncoder(writer)

	numKeys := len(configKeys)

	err := enc.WriteCompactU16(numKeys)
	if err != nil {
		panic("shouldn't error")
	}

	for _, ck := range configKeys {
		err = ck.MarshalWithEncoder(enc)
		if err != nil {
			panic("shouldn't fail")
		}
	}
	return writer.Bytes()
}

func signerOnlyConfigKeys(configKeys []ConfigKey) []ConfigKey {
	var signerKeys []ConfigKey
	for _, ck := range configKeys {
		if ck.IsSigner {
			signerKeys = append(signerKeys, ck)
		}
	}
	return signerKeys
}

func deduplicateConfigKeySigners(configKeys []ConfigKey) []ConfigKey {

	var dedupeConfigKeys []ConfigKey
	cm := make(map[solana.PublicKey]bool)

	for _, ck := range configKeys {
		_, alreadyExists := cm[ck.Pubkey]
		if !alreadyExists {
			dedupeConfigKeys = append(dedupeConfigKeys, ck)
			cm[ck.Pubkey] = true
		}
	}
	return dedupeConfigKeys
}

func ConfigProgramExecute(ctx *ExecutionCtx) error {
	klog.Infof("Config program")

	var err error

	err = ctx.ComputeMeter.Consume(CUConfigProcessorDefaultComputeUnits)
	if err != nil {
		return InstrErrComputationalBudgetExceeded
	}

	txCtx := ctx.TransactionContext
	instrCtx, err := txCtx.CurrentInstructionCtx()
	if err != nil {
		return err
	}

	instrData := instrCtx.Data
	configKeys, err := unmarshalConfigKeys(instrData, true)
	if err != nil {
		return InstrErrInvalidInstructionData
	}

	idx, err := instrCtx.IndexOfInstructionAccountInTransaction(0)
	if err != nil {
		return err
	}
	configAccountKey, err := txCtx.KeyOfAccountAtIndex(idx)
	if err != nil {
		return err
	}

	configAccount, err := instrCtx.BorrowInstructionAccount(ctx.TransactionContext, 0)
	if err != nil {
		return err
	}
	defer configAccount.Drop()

	if configAccount.Owner() != ConfigProgramAddr {
		return InstrErrInvalidAccountOwner
	}

	configAcctIsSigner := configAccount.IsSigner()

	configAcctData := configAccount.Data()
	currentConfigKeys, err := unmarshalConfigKeys(configAcctData, false)
	if err != nil {
		return InstrErrInvalidAccountData
	}
	configAccount.Drop()

	currentSignerKeys := signerOnlyConfigKeys(currentConfigKeys)
	if len(currentSignerKeys) == 0 && !configAcctIsSigner {
		return InstrErrMissingRequiredSignature
	}

	signerKeys := signerOnlyConfigKeys(configKeys)
	var counter uint64
	for _, signerKey := range signerKeys {
		counter++
		if signerKey.Pubkey != configAccountKey {
			signerAcct, err := instrCtx.BorrowInstructionAccount(txCtx, counter)
			if err != nil {
				return InstrErrMissingRequiredSignature
			}
			defer signerAcct.Drop()

			if !signerAcct.IsSigner() {
				return InstrErrMissingRequiredSignature
			}
			if signerKey.Pubkey != signerAcct.Key() {
				return InstrErrMissingRequiredSignature
			}

			if len(currentConfigKeys) != 0 {
				matchFound := false
				for _, s := range currentSignerKeys {
					if s.Pubkey == signerKey.Pubkey {
						signerAcct.Drop()
						matchFound = true
						break
					}
				}
				if !matchFound {
					return InstrErrMissingRequiredSignature
				}
			}
			signerAcct.Drop()
		} else if !configAcctIsSigner {
			return InstrErrMissingRequiredSignature
		}
	}

	totalNewConfigKeys := len(configKeys)
	uniqueNewConfigKeys := len(deduplicateConfigKeySigners(configKeys))
	if totalNewConfigKeys != uniqueNewConfigKeys {
		return InstrErrInvalidArgument
	}

	if len(currentSignerKeys) > int(counter) {
		return InstrErrMissingRequiredSignature
	}

	configAccount, err = instrCtx.BorrowInstructionAccount(txCtx, 0)
	if err != nil {
		return err
	}
	defer configAccount.Drop()

	if len(configAccount.Data()) < len(instrData) {
		return InstrErrInvalidInstructionData
	}

	klog.Infof("writing new config account state")
	err = configAccount.SetData(ctx.GlobalCtx.Features, instrData)
	return err
}
