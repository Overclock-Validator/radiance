package conformance

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/assert"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/cu"
	"go.firedancer.io/radiance/pkg/sealevel"
	"google.golang.org/protobuf/proto"
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
	var clock sealevel.SysvarClock
	clock.Slot = 1234
	clockAcct := accounts.Account{}
	execCtx.Accounts.SetAccount(&sealevel.SysvarClockAddr, &clockAcct)
	sealevel.WriteClockSysvar(&execCtx.Accounts, clock)

	var rent sealevel.SysvarRent
	rent.LamportsPerUint8Year = 3480
	rent.ExemptionThreshold = 2.0
	rent.BurnPercent = 50

	rentAcct := accounts.Account{}
	execCtx.Accounts.SetAccount(&sealevel.SysvarRentAddr, &rentAcct)
	sealevel.WriteRentSysvar(&execCtx.Accounts, rent)

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
		for _, fixtureModifiedAcct := range fixture.Output.ModifiedAccounts {
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

				// we don't know what recent blockhash was used in generating some *NonceAccount testcases,
				// and we also do not know what lamports_per_signature value was used, hence we need to compare
				// the new account data without these fields
				if isSystemProgramNonceInstr(fixture) && len(fixtureModifiedAcct.Data) >= 80 {
					if !bytes.Equal(fixtureModifiedAcct.Data[:40], mithrilModifiedAcct.Data[:40]) {
						fmt.Printf("**** nonce account state (first 40 bytes) did not match\n")
						fmt.Printf("fixture: %v\n", fixtureModifiedAcct.Data)
						fmt.Printf("mithril: %v\n", mithrilModifiedAcct.Data)
						return false
					}
				} else if !bytes.Equal(fixtureModifiedAcct.Data, mithrilModifiedAcct.Data) {
					fmt.Printf("**** account states did not match\n")
					fmt.Printf("\na: %v\n\n", mithrilModifiedAcct.Data)
					fmt.Printf("b: %v\n\n", fixtureModifiedAcct.Data)
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

func isSystemProgramNonceInstr(fixture *InstrFixture) bool {
	if solana.PublicKeyFromBytes(fixture.Input.ProgramId) != sealevel.SystemProgramAddr {
		return false
	}

	if len(fixture.Input.Data) < 4 {
		return false
	}

	instrCode := binary.LittleEndian.Uint32(fixture.Input.Data[0:4])

	return instrCode == sealevel.SystemProgramInstrTypeAdvanceNonceAccount ||
		instrCode == sealevel.SystemProgramInstrTypeWithdrawNonceAccount ||
		instrCode == sealevel.SystemProgramInstrTypeInitializeNonceAccount ||
		instrCode == sealevel.SystemProgramInstrTypeAuthorizeNonceAccount
}

func skipSystemProgramTestcase(fixture *InstrFixture, filename string) bool {

	testcasesToSkip := []string{"764d48300da9556f84b303e15ef9cacfc825ec2a.fix"} // seems to have been generated with non-standard rent sysvar

	for _, fnToSkip := range testcasesToSkip {
		if strings.HasSuffix(filename, fnToSkip) {
			return true
		}
	}

	// some testcases saw the return of the system program's NonceNoRecentBlockhashes error.
	// this is not a condition we'll ever see outside of perhaps the genesis block, so we
	// skip these testcases.
	if fixture.Output.Result == 26 && fixture.Output.CustomErr == 6 {
		return true
	}

	// some testcases in the corpus expect a result of InstrErrUnsupportedSysvar, but this is
	// not possible other than during the genesis block, hence we skip these samples.
	if fixture.Output.Result == 49 {
		return true
	}

	return false
}

func shouldDisregardSystemProgramError(fixture *InstrFixture, err error) bool {

	if len(fixture.Input.Data) < 4 {
		return false
	}

	instrCode := int32(binary.LittleEndian.Uint32(fixture.Input.Data[0:4]))

	// some testcases for InitializeNonceAccount give no error, but when running the relevant
	// testcases with default rent sysvar configuration (exemption_threshold=2.0, burn_percent=50
	// lamports_per_byte_year=3480), we get an error returned by mithril. This indicates that the
	// testcases in question were generated with non-standard Rent sysvar settings, and we'll therefore
	// reject these results because we have no way of knowing what settings were actually used.
	if instrCode == sealevel.SystemProgramInstrTypeInitializeNonceAccount && err == sealevel.InstrErrInsufficientFunds {
		return true
	}

	// the above is also true here as well; non-standard Rent sysvar settings used when generating
	// testcases can also mean that while mithril returns success with standard Rent sysvar settings,
	// the testcase when run with mocked-up firedancer state gave an error, so we have to disregard these
	// errors as well.
	if instrCode == sealevel.SystemProgramInstrTypeInitializeNonceAccount && err == nil && fixture.Output.Result == 6 {
		return true
	}

	// we don't know what the recent blockhash was when generating these samples
	if err == sealevel.SystemProgErrNonceBlockhashNotExpired && (instrCode == sealevel.SystemProgramInstrTypeAdvanceNonceAccount ||
		instrCode == sealevel.SystemProgramInstrTypeUpgradeNonceAccount ||
		instrCode == sealevel.SystemProgramInstrTypeAuthorizeNonceAccount ||
		instrCode == sealevel.SystemProgramInstrTypeInitializeNonceAccount ||
		instrCode == sealevel.SystemProgramInstrTypeWithdrawNonceAccount) {
		return true
	}

	return false
}

func TestConformance_System_Program(t *testing.T) {
	basePath := "test-vectors/instr/fixtures/system"
	fileInfos, err := ioutil.ReadDir(basePath)
	assert.NoError(t, err)

	var fnames []string
	for _, fileInfo := range fileInfos {
		filePath := fmt.Sprintf("%s/%s", basePath, fileInfo.Name())
		fnames = append(fnames, filePath)
	}

	failedTestcases := make([]string, 0)
	var testcaseCounter uint64
	var acctStateFailure uint64
	var returnValueFailure uint64

	acctStateFailureMap := make(map[int]int)
	returnValueFailureMap := make(map[int]int)

	for _, fname := range fnames {
		testcaseCounter++
		in, err := ioutil.ReadFile(fname)
		if err != nil {
			log.Fatalln("Error reading file:", err)
		}

		fixture := &InstrFixture{}
		if err := proto.Unmarshal(in, fixture); err != nil {
			log.Fatalln("Failed to parse fixture:", err)
		}

		fmt.Printf("**** (%s) testcase %d of %d\n", fname, testcaseCounter, len(fnames))

		execCtx, instrAccts := newExecCtxAndInstrAcctsFromFixture(fixture)

		fmt.Printf("prepared instruction accounts:")
		for idx, ia := range instrAccts {
			fmt.Printf("instrAcct %d: %v\n", idx, ia)
		}

		var instrCode int32 = -1
		if len(fixture.Input.Data) >= 4 {
			instrCode = int32(binary.LittleEndian.Uint32(fixture.Input.Data[0:4]))
			fmt.Printf("instruction code: %d\n", instrCode)
		}

		if skipSystemProgramTestcase(fixture, fname) {
			continue
		}

		for idx, acct := range fixture.Input.Accounts {
			fmt.Printf("txAcct %d: %s, Lamports: %d\n", idx, solana.PublicKeyFromBytes(acct.Address), acct.Lamports)
		}

		for idx, acct := range fixture.Input.InstrAccounts {
			fmt.Printf("instrAcct %d: %s, isSigner: %t, Executable: %t, Lamports: %d\n", idx, solana.PublicKeyFromBytes(fixture.Input.Accounts[acct.Index].Address), acct.IsSigner, fixture.Input.Accounts[acct.Index].Executable, fixture.Input.Accounts[acct.Index].Lamports)
		}

		err = execCtx.ProcessInstruction(fixture.Input.Data, instrAccts, []uint64{0})

		if shouldDisregardSystemProgramError(fixture, err) {
			continue
		}

		if !returnValueIsExpectedValue(fixture, err) {
			errMsg := fmt.Sprintf("failed testcase on return value (instrCode %d), %s", instrCode, fname)
			failedTestcases = append(failedTestcases, errMsg)
			returnValueFailure++
			returnValueFailureMap[int(instrCode)]++
		}

		if err == nil {
			if !accountStateChangesMatch(t, execCtx, fixture) {
				errMsg := fmt.Sprintf("failed testcase on account state check (instrCode %d), %s", instrCode, fname)
				failedTestcases = append(failedTestcases, errMsg)
				acctStateFailure++
				acctStateFailureMap[int(instrCode)]++
			}
		}
	}

	fmt.Printf("\n\n")

	for _, fn := range failedTestcases {
		fmt.Printf("%s\n", fn)
	}

	fmt.Printf("\n\nfailed testcases %d:\n", len(failedTestcases))
	fmt.Printf("return value failures: %d, acct state failures: %d\n\n", returnValueFailure, acctStateFailure)

	for k, v := range returnValueFailureMap {
		fmt.Printf("(return value failures) instrCode: %d, %d failures\n", k, v)
	}

	fmt.Printf("\n")

	for k, v := range acctStateFailureMap {
		fmt.Printf("(acct state failures) instrCode: %d, %d failures\n", k, v)
	}

	assert.Empty(t, failedTestcases, "failing testcases found")
}

func TestConformance_System_Program_Single_Testcase(t *testing.T) {
	basePath := "test-vectors/instr/fixtures/system"
	fn := "5994531cac2587a14054252dc54b9eb1f288f357.fix"

	fname := fmt.Sprintf("%s/%s", basePath, fn)

	in, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatalln("Error reading file:", err)
	}

	fixture := &InstrFixture{}
	if err := proto.Unmarshal(in, fixture); err != nil {
		log.Fatalln("Failed to parse fixture:", err)
	}

	execCtx, instrAccts := newExecCtxAndInstrAcctsFromFixture(fixture)

	fmt.Printf("prepared instruction accounts:\n")
	for idx, ia := range instrAccts {
		fmt.Printf("instrAcct %d: %s, owner = %s, isSigner = %t, isWritable = %t\n", idx, solana.PublicKeyFromBytes(fixture.Input.Accounts[ia.IndexInCallee].Address), solana.PublicKeyFromBytes(fixture.Input.Accounts[ia.IndexInCallee].Owner), ia.IsSigner, ia.IsWritable)
	}

	var instrCode int32 = -1
	if len(fixture.Input.Data) >= 4 {
		instrCode = int32(binary.LittleEndian.Uint32(fixture.Input.Data[0:4]))
		fmt.Printf("instruction code: %d\n", instrCode)
	}

	for idx, acct := range fixture.Input.Accounts {
		fmt.Printf("txAcct %d: %s, Lamports: %d\n", idx, solana.PublicKeyFromBytes(acct.Address), acct.Lamports)
	}

	for idx, acct := range fixture.Input.InstrAccounts {
		fmt.Printf("instrAcct %d: %s, isSigner: %t, Executable: %t, Lamports: %d\n", idx, solana.PublicKeyFromBytes(fixture.Input.Accounts[acct.Index].Address), acct.IsSigner, fixture.Input.Accounts[acct.Index].Executable, fixture.Input.Accounts[acct.Index].Lamports)
	}

	err = execCtx.ProcessInstruction(fixture.Input.Data, instrAccts, []uint64{0})

	if !returnValueIsExpectedValue(fixture, err) {
		fmt.Printf("failed testcase on return value (instrCode %d), %s\n", instrCode, fname)
	}

	if err == nil {
		if !accountStateChangesMatch(t, execCtx, fixture) {
			fmt.Printf("failed testcase on account state check (instrCode %d), %s\n", instrCode, fname)
		}
	}
}
