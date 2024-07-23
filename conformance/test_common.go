package conformance

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/assert"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/cu"
	"go.firedancer.io/radiance/pkg/features"
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

func configureSysvars(execCtx *sealevel.ExecutionCtx, fixture *InstrFixture) {
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
			fmt.Printf("adding state for sysvar: SysvarEpochSchedule\n")
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
			fmt.Printf("adding state for sysvar: SysvarEpochRewards\n")
			epochRewardsAcct := fixtureAcctStateToAccount(acct)
			execCtx.Accounts.SetAccount(&sealevel.SysvarEpochRewardsAddr, &epochRewardsAcct)
		}
	}

	/// RecentBlockhashes
	for _, acct := range fixture.Input.Accounts {
		if solana.PublicKeyFromBytes(acct.Address) == sealevel.SysvarRecentBlockHashesAddr {
			fmt.Printf("adding state for sysvar: SysvarRecentBlockhashes\n")
			recentBlockhashesAcct := fixtureAcctStateToAccount(acct)
			execCtx.Accounts.SetAccount(&sealevel.SysvarRecentBlockHashesAddr, &recentBlockhashesAcct)
			rbh, err := sealevel.ReadRecentBlockHashesSysvar(&execCtx.Accounts)
			if err == nil {
				if len(rbh) != 0 {
					execCtx.Blockhash = rbh[len(rbh)-1].Blockhash
					execCtx.LamportsPerSignature = rbh[len(rbh)-1].FeeCalculator.LamportsPerSignature
				}
			} else {
				execCtx.LamportsPerSignature = 5000
			}
		}
	}
}

func parseAndConfigureFeatures(execCtx *sealevel.ExecutionCtx, fixture *InstrFixture) {
	f := features.NewFeaturesDefault()
	execCtx.GlobalCtx.Features = *f

	for _, ftr := range fixture.Input.EpochContext.Features.Features {
		for _, featureGate := range features.AllFeatureGates {
			featureIdInt := binary.LittleEndian.Uint64(featureGate.Address[:8])
			if featureIdInt == ftr {
				execCtx.GlobalCtx.Features.EnableFeature(featureGate, 0)
			}
		}
	}
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
	configureSysvars(&execCtx, fixture)
	parseAndConfigureFeatures(&execCtx, fixture)

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

func accountStateChangesMatch(t *testing.T, execCtx *sealevel.ExecutionCtx, fixture *InstrFixture) bool {
	txCtx := execCtx.TransactionContext
	acctsModified := make([]accounts.Account, 0)

	for idx, touched := range txCtx.Accounts.Touched {
		if touched {
			touchedAcct, err := txCtx.Accounts.GetAccount(uint64(idx))
			assert.NoError(t, err)
			acctsModified = append(acctsModified, *touchedAcct)
		}
	}

	for _, mithrilModifiedAcct := range acctsModified {
		var modifiedAcctFoundInTestcase bool
		for modifiedAcctIdx, fixtureModifiedAcct := range fixture.Output.ModifiedAccounts {
			if solana.PublicKeyFromBytes(fixtureModifiedAcct.Address) == mithrilModifiedAcct.Key {
				modifiedAcctFoundInTestcase = true
				if fixtureModifiedAcct.Lamports != mithrilModifiedAcct.Lamports {
					return false
				}
				if fixtureModifiedAcct.Executable != mithrilModifiedAcct.Executable {
					return false
				}
				if fixtureModifiedAcct.RentEpoch != mithrilModifiedAcct.RentEpoch {
					return false
				}
				if solana.PublicKeyFromBytes(fixtureModifiedAcct.Owner[:]) != solana.PublicKeyFromBytes(mithrilModifiedAcct.Owner[:]) {
					return false
				}

				if !bytes.Equal(fixtureModifiedAcct.Data, mithrilModifiedAcct.Data) {
					fmt.Printf("**** %d: account states did not match\n", modifiedAcctIdx)
					fmt.Printf("\na (%d bytes): %v\n\n", len(mithrilModifiedAcct.Data), mithrilModifiedAcct.Data)
					fmt.Printf("b (%d bytes): %v\n\n", len(fixtureModifiedAcct.Data), fixtureModifiedAcct.Data)

					mithrilState, err := sealevel.UnmarshalNonceStateVersions(mithrilModifiedAcct.Data)
					if err != nil {
						return false
					}
					fixtureState, err := sealevel.UnmarshalNonceStateVersions(fixtureModifiedAcct.Data)
					if err != nil {
						return false
					}

					fmt.Printf("\nmithril state: %+v\n\n", mithrilState)
					fmt.Printf("fixture state: %+v\n\n", fixtureState)

					return false
				}
			}
		}
		if !modifiedAcctFoundInTestcase {
			postBytes := mithrilModifiedAcct.Data
			var preBytes []byte

			foundAcct := false
			for _, acct := range fixture.Input.Accounts {
				if mithrilModifiedAcct.Key == solana.PublicKeyFromBytes(acct.Address) {
					preBytes = acct.Data
					foundAcct = true
					break
				}
			}
			if !foundAcct {
				t.Fatalf("pre-account not found. should never happen.")
			}

			if !bytes.Equal(postBytes, preBytes) {
				fmt.Printf("len(pre) %d vs len(post) %d\n", len(preBytes), len(postBytes))
				return false
			}
		}
	}

	return true
}

func instrCodeFromFixtureInstrData(fixture *InstrFixture) int32 {
	var instrCode int32 = -1
	if len(fixture.Input.Data) >= 4 {
		instrCode = int32(binary.LittleEndian.Uint32(fixture.Input.Data[0:4]))
	}
	return instrCode
}

func printFixtureInfo(fixture *InstrFixture) {
	instrCode := instrCodeFromFixtureInstrData(fixture)
	fmt.Printf("instruction code: %d\n", instrCode)

	for idx, acct := range fixture.Input.Accounts {
		fmt.Printf("txAcct %d: %s, Lamports: %d\n", idx, solana.PublicKeyFromBytes(acct.Address), acct.Lamports)
	}

	for idx, acct := range fixture.Input.InstrAccounts {
		fmt.Printf("instrAcct %d: %s, isSigner: %t, isWritable: %t, Executable: %t, Lamports: %d\n", idx, solana.PublicKeyFromBytes(fixture.Input.Accounts[acct.Index].Address), acct.IsSigner, acct.IsWritable, fixture.Input.Accounts[acct.Index].Executable, fixture.Input.Accounts[acct.Index].Lamports)
	}
}
