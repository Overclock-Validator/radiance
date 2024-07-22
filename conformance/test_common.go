package conformance

import (
	"fmt"

	"github.com/gagliardetto/solana-go"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/cu"
	"go.firedancer.io/radiance/pkg/sealevel"
)

func fixtureAcctStateToAccount(acctState *AcctState) accounts.Account {
	var acct accounts.Account
	acct.Key = solana.PublicKeyFromBytes(acctState.Address[:])
	acct.Lamports = acctState.Lamports
	acct.Data = acctState.Data
	acct.Executable = acctState.Executable
	acct.RentEpoch = acctState.RentEpoch
	copy(acct.Owner[:], acctState.Owner)
	return acct
}

func createProgramAcct(programId []byte) accounts.Account {
	programKey := solana.PublicKeyFromBytes(programId)
	programAcct := accounts.Account{Key: programKey, Lamports: 100000000, Data: make([]byte, 0), Owner: sealevel.NativeLoaderAddr, Executable: true, RentEpoch: 100}
	return programAcct
}

func instructionAcctsFromFixture(fixture *InstrFixture, transactionAccts sealevel.TransactionAccounts) []sealevel.InstructionAccount {
	accts := fixture.Input.Accounts
	fixtureInstrAccts := fixture.Input.InstrAccounts

	acctMetas := make([]sealevel.AccountMeta, 0)
	for count := 0; count < len(fixtureInstrAccts); count++ {
		thisInstrAcct := fixtureInstrAccts[count]
		acctKey := accts[thisInstrAcct.Index].Address
		acctMeta := sealevel.AccountMeta{Pubkey: solana.PublicKeyFromBytes(acctKey), IsSigner: fixtureInstrAccts[count].IsSigner, IsWritable: fixtureInstrAccts[count].IsWritable}
		acctMetas = append(acctMetas, acctMeta)
	}

	instructionAccts := sealevel.InstructionAcctsFromAccountMetas(acctMetas, transactionAccts)
	return instructionAccts
}

func newExecCtxAndInstrAcctsFromFixture(fixture *InstrFixture) (*sealevel.ExecutionCtx, []sealevel.InstructionAccount) {

	programAcct := createProgramAcct(fixture.Input.ProgramId)
	accts := make([]accounts.Account, 0)

	for count := 0; count < len(fixture.Input.Accounts); count++ {
		acct := fixtureAcctStateToAccount(fixture.Input.Accounts[count])
		accts = append(accts, acct)
	}

	acctsForTx := make([]accounts.Account, 0)
	acctsForTx = append(acctsForTx, programAcct)
	acctsForTx = append(acctsForTx, accts...)

	transactionAccts := sealevel.NewTransactionAccounts(acctsForTx)
	instrAccts := instructionAcctsFromFixture(fixture, *transactionAccts)

	txCtx := sealevel.NewTestTransactionCtx(*transactionAccts, 5, 64)

	execCtx := sealevel.ExecutionCtx{TransactionContext: txCtx, ComputeMeter: cu.NewComputeMeter(fixture.Input.CuAvail)}

	execCtx.Accounts = accounts.NewMemAccounts()

	// set the sysvars up
	/// clock
	var foundClockSysvar bool
	for _, acct := range fixture.Input.Accounts {
		if solana.PublicKeyFromBytes(acct.Address) == sealevel.SysvarClockAddr {
			fmt.Printf("adding state for sysvar: Clock\n")
			clockAcct := fixtureAcctStateToAccount(acct)
			execCtx.Accounts.SetAccount(&sealevel.SysvarClockAddr, &clockAcct)
			foundClockSysvar = true
		}
	}

	if !foundClockSysvar {
		var clock sealevel.SysvarClock
		clock.Slot = 10
		clockAcct := accounts.Account{}
		execCtx.Accounts.SetAccount(&sealevel.SysvarClockAddr, &clockAcct)
		sealevel.WriteClockSysvar(&execCtx.Accounts, clock)
	}

	/// rent
	var foundRentSysvar bool
	for _, acct := range fixture.Input.Accounts {
		if solana.PublicKeyFromBytes(acct.Address) == sealevel.SysvarRentAddr {
			fmt.Printf("adding state for sysvar: Rent\n")
			rentAcct := fixtureAcctStateToAccount(acct)
			execCtx.Accounts.SetAccount(&sealevel.SysvarRentAddr, &rentAcct)
			foundRentSysvar = true
		}
	}

	if !foundRentSysvar {
		var rent sealevel.SysvarRent
		rent.LamportsPerUint8Year = 3480
		rent.ExemptionThreshold = 2.0
		rent.BurnPercent = 50

		rentAcct := accounts.Account{}
		execCtx.Accounts.SetAccount(&sealevel.SysvarRentAddr, &rentAcct)
		sealevel.WriteRentSysvar(&execCtx.Accounts, rent)
	}

	/// SlotHashes
	for _, acct := range fixture.Input.Accounts {
		if solana.PublicKeyFromBytes(acct.Address) == sealevel.SysvarSlotHashesAddr {
			fmt.Printf("adding state for sysvar: SlotHashes\n")
			slotHashesAcct := fixtureAcctStateToAccount(acct)
			execCtx.Accounts.SetAccount(&sealevel.SysvarSlotHashesAddr, &slotHashesAcct)
		}
	}

	/// StakeHistory
	for _, acct := range fixture.Input.Accounts {
		if solana.PublicKeyFromBytes(acct.Address) == sealevel.SysvarStakeHistoryAddr {
			fmt.Printf("adding state for sysvar: StakeHistory\n")
			stakeHistoryAcct := fixtureAcctStateToAccount(acct)
			execCtx.Accounts.SetAccount(&sealevel.SysvarStakeHistoryAddr, &stakeHistoryAcct)
		}
	}

	/// EpochSchedule
	var foundEpochScheduleSysvar bool
	for _, acct := range fixture.Input.Accounts {
		if solana.PublicKeyFromBytes(acct.Address) == sealevel.SysvarEpochScheduleAddr {
			fmt.Printf("adding state for sysvar: SysvarEpochScheduleAddr\n")
			epochScheduleAcct := fixtureAcctStateToAccount(acct)
			execCtx.Accounts.SetAccount(&sealevel.SysvarEpochScheduleAddr, &epochScheduleAcct)
			foundEpochScheduleSysvar = true
		}
	}

	if !foundEpochScheduleSysvar {
		epochSchedule := sealevel.SysvarEpochSchedule{SlotsPerEpoch: 432000, LeaderScheduleSlotOffset: 432000, Warmup: true, FirstNormalEpoch: 14, FirstNormalSlot: 524256}

		epochScheduleAcct := accounts.Account{}
		execCtx.Accounts.SetAccount(&sealevel.SysvarEpochScheduleAddr, &epochScheduleAcct)
		sealevel.WriteEpochScheduleSysvar(&execCtx.Accounts, epochSchedule)
	}

	/// EpochRewards
	for _, acct := range fixture.Input.Accounts {
		if solana.PublicKeyFromBytes(acct.Address) == sealevel.SysvarEpochRewardsAddr {
			fmt.Printf("adding state for sysvar: SysvarEpochRewardsAddr\n")
			epochRewardsAcct := fixtureAcctStateToAccount(acct)
			execCtx.Accounts.SetAccount(&sealevel.SysvarEpochRewardsAddr, &epochRewardsAcct)
		}
	}

	execCtx.SysvarCache.PopulateRecentBlockHashesForTesting()
	execCtx.LamportsPerSignature = 5000

	return &execCtx, instrAccts
}

func returnValueIsExpectedValue(fixture *InstrFixture, err error) bool {
	fmt.Printf("assertReturnValueIsExpected: err %s, result %d, customErr %d\n", err, fixture.Output.Result, fixture.Output.CustomErr)
	if err == nil && fixture.Output.Result == 0 {
		fmt.Printf("err == nil && fixture.Output.Result == 0\n")
		return true
	} else if err == nil && fixture.Output.Result != 0 {
		fmt.Printf("mithril returned success, and testcase reported %d\n", fixture.Output.Result)
		return false
	}

	// for errors other than instruction errors, the custom error field is used
	if fixture.Output.Result == 26 && sealevel.IsCustomErr(err) {
		return uint32(sealevel.TranslateErrToErrCode(err)) == fixture.Output.CustomErr
	} else {
		// plus 1 because firedancer err codes are deliberately off-by-one to allow for signaling success via 0
		// whilst InstrErrGenericErr is also 0 in Agave
		returnedSolanaErrCode := int32(sealevel.TranslateErrToErrCode(err) + 1)
		matches := fixture.Output.Result == returnedSolanaErrCode
		if !matches {
			fmt.Printf("mithril returned %s, result %d, customErr %d\n", err, fixture.Output.Result, fixture.Output.CustomErr)
			return false
		} else {
			return true
		}
	}
}
