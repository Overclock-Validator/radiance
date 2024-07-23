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
	"go.firedancer.io/radiance/pkg/sealevel"
	"google.golang.org/protobuf/proto"
)

func systemAccountStateChangesMatch(t *testing.T, execCtx *sealevel.ExecutionCtx, fixture *InstrFixture) bool {
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

		execCtx, instrAccts := newExecCtxAndInstrAcctsFromFixture(fixture)

		printFixtureInfo(fixture)

		err = execCtx.ProcessInstruction(fixture.Input.Data, instrAccts, []uint64{0})

		instrCode := instrCodeFromFixtureInstrData(fixture)

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

	fmt.Printf("\n\nfailed testcases %d / %d:\n", len(failedTestcases), len(fnames))
	fmt.Printf("return value failures: %d, acct state failures: %d\n\n", returnValueFailure, acctStateFailure)

	for k, v := range returnValueFailureMap {
		fmt.Printf("(return value failures) instrCode: %d, %d failures\n", k, v)
	}

	fmt.Printf("\n")

	for k, v := range acctStateFailureMap {
		fmt.Printf("(acct state failures) instrCode: %d, %d failures\n", k, v)
	}

	hasFailedTestcases := len(failedTestcases) != 0
	assert.Equal(t, false, hasFailedTestcases, "failing testcases found")
}

func TestConformance_System_Program_Single_Testcase(t *testing.T) {
	basePath := "test-vectors/instr/fixtures/system"
	fn := "0d25312f08d93023e6eccdf8f4f62155b9c7756b_3157987.fix"

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

	printFixtureInfo(fixture)

	err = execCtx.ProcessInstruction(fixture.Input.Data, instrAccts, []uint64{0})

	instrCode := instrCodeFromFixtureInstrData(fixture)

	if !returnValueIsExpectedValue(fixture, err) {
		fmt.Printf("failed testcase on return value (instrCode %d), %s\n", instrCode, fname)
	}

	if err == nil {
		if !accountStateChangesMatch(t, execCtx, fixture) {
			fmt.Printf("failed testcase on account state check (instrCode %d), %s\n", instrCode, fname)
		}
	}
}
