package sealevel

import (
	"bytes"
	"testing"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/assert"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/cu"
	"k8s.io/klog/v2"
)

func TestExecute_Tx_System_Program_CreateAccount_Success(t *testing.T) {

	// system program acct
	systemProgramAcct := accounts.Account{Key: SystemProgramAddr, Lamports: 100000000, Data: make([]byte, 0), Owner: NativeLoaderAddr, Executable: true, RentEpoch: 100}

	// funding acct
	fundingAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	fundingPubkey := fundingAcctPrivateKey.PublicKey()
	fundingAcct := accounts.Account{Key: fundingPubkey, Lamports: 10000, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	// new acct
	newAcctPrivateKey, err := solana.NewRandomPrivateKey()
	assert.NoError(t, err)
	newPubkey := newAcctPrivateKey.PublicKey()
	newAcct := accounts.Account{Key: newPubkey, Lamports: 0, Data: make([]byte, 0), Owner: SystemProgramAddr, Executable: false, RentEpoch: 100}

	var createAcct SystemInstrCreateAccount
	createAcct.Lamports = 1234
	createAcct.Owner = BpfLoaderUpgradeableAddr
	createAcct.Space = 1234

	createAcctInstrWriter := new(bytes.Buffer)
	createAcctEncoder := bin.NewBinEncoder(createAcctInstrWriter)

	err = createAcct.MarshalWithEncoder(createAcctEncoder)
	assert.NoError(t, err)
	instrBytes := createAcctInstrWriter.Bytes()

	transactionAccts := NewTransactionAccounts([]accounts.Account{systemProgramAcct, fundingAcct, newAcct})

	acctMetas := []AccountMeta{{Pubkey: fundingAcct.Key, IsSigner: true, IsWritable: true},
		{Pubkey: newAcct.Key, IsSigner: true, IsWritable: true}}

	instructionAccts := instructionAcctsFromAccountMetas(acctMetas, *transactionAccts)

	txCtx := NewTestTransactionCtx(*transactionAccts, 5, 64)
	execCtx := ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(10000000000)}

	execCtx.Accounts = accounts.NewMemAccounts()
	var clock SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	execCtx.Accounts.SetAccount(&SysvarClockAddr, &clockAcct)
	WriteClockSysvar(&execCtx.Accounts, clock)

	var rent SysvarRent
	rent.LamportsPerUint8Year = 1
	rent.ExemptionThreshold = 1
	rent.BurnPercent = 0

	rentAcct := accounts.Account{}
	execCtx.Accounts.SetAccount(&SysvarRentAddr, &rentAcct)
	WriteRentSysvar(&execCtx.Accounts, rent)

	klog.Infof("pubkey: %s, %s", fundingAcct.Key, newAcct.Key)
	err = execCtx.ProcessInstruction(instrBytes, instructionAccts, []uint64{0})
	assert.NoError(t, err)

	newAcctPost, err := txCtx.Accounts.GetAccount(2)
	assert.NoError(t, err)

	// check new account has lamports, space and owner as expected
	assert.Equal(t, createAcct.Lamports, newAcctPost.Lamports)
	assert.Equal(t, createAcct.Space, uint64(len(newAcctPost.Data)))
	assert.Equal(t, createAcct.Owner, solana.PublicKeyFromBytes(newAcctPost.Owner[:]))

	fundingAcctPost, err := txCtx.Accounts.GetAccount(1)
	assert.NoError(t, err)

	// check that the funder account balance has changed accordingly
	assert.Equal(t, fundingAcct.Lamports-createAcct.Lamports, fundingAcctPost.Lamports)
}
