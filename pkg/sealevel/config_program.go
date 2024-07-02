package sealevel

import (
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"k8s.io/klog/v2"
)

type ConfigKey struct {
	PubKey   solana.PublicKey
	IsSigner bool
}

func (configKey *ConfigKey) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	pubKey, err := decoder.ReadBytes(solana.PublicKeyLength)
	if err != nil {
		return err
	}
	copy(configKey.PubKey[:], pubKey)

	isSignerByte, err := decoder.ReadByte()
	if err != nil {
		return err
	}

	if isSignerByte == 1 {
		configKey.IsSigner = true
	} else if isSignerByte == 0 {
		configKey.IsSigner = false
	} else {
		return SyscallErrMalformedBool
	}

	return nil
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
		_, alreadyExists := cm[ck.PubKey]
		if !alreadyExists {
			dedupeConfigKeys = append(dedupeConfigKeys, ck)
		}
	}
	return dedupeConfigKeys
}

func ConfigProgramExecute(ctx *ExecutionCtx) error {
	klog.Infof("in Config program")
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

	configAcctData := configAccount.Data()
	currentConfigKeys, err := unmarshalConfigKeys(configAcctData, false)
	if err != nil {
		return InstrErrInvalidAccountData
	}
	configAccount.Drop()

	currentSignerKeys := signerOnlyConfigKeys(currentConfigKeys)
	if len(currentSignerKeys) == 0 && !configAccount.IsSigner() {
		return InstrErrMissingRequiredSignature
	}

	signerKeys := signerOnlyConfigKeys(configKeys)
	var counter uint64
	for _, signerKey := range signerKeys {
		counter++
		if signerKey.PubKey != configAccountKey {
			signerAcct, err := instrCtx.BorrowInstructionAccount(txCtx, counter)
			if err != nil {
				return InstrErrMissingRequiredSignature
			}
			defer signerAcct.Drop()

			if !signerAcct.IsSigner() {
				return InstrErrMissingRequiredSignature
			}
			if signerKey.PubKey != signerAcct.Key() {
				return InstrErrMissingRequiredSignature
			}

			if len(currentConfigKeys) != 0 {
				matchFound := false
				for _, s := range currentSignerKeys {
					if s.PubKey == signerKey.PubKey {
						matchFound = true
						break
					}
				}
				if !matchFound {
					return InstrErrMissingRequiredSignature
				}
			}
		} else if !configAccount.IsSigner() {
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

	if len(configAccount.Data()) < len(instrData) {
		return InstrErrInvalidInstructionData
	}

	err = configAccount.SetData(ctx.GlobalCtx.Features, instrData)
	return err
}
