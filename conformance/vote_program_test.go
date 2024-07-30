package conformance

import (
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/cu"
	"go.firedancer.io/radiance/pkg/sealevel"
	"google.golang.org/protobuf/proto"
)

func newExecCtxAndInstrAcctsFromFixtureForVote(fixture *InstrFixture) (*sealevel.ExecutionCtx, []sealevel.InstructionAccount) {

	programAcct := createProgramAcct(sealevel.VoteProgramAddr[:])
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

func TestConformance_Vote_Program(t *testing.T) {
	basePath := "test-vectors/instr/fixtures/vote"
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
		in, err := ioutil.ReadFile(fname)
		if err != nil {
			log.Fatalln("Error reading file:", err)
		}

		fixture := &InstrFixture{}
		if err := proto.Unmarshal(in, fixture); err != nil {
			log.Fatalln("Failed to parse fixture:", err)
		}

		fmt.Printf("testcase file: %s\n", fname)

		execCtx, instrAccts := newExecCtxAndInstrAcctsFromFixture(fixture)

		printFixtureInfo(fixture)

		err = execCtx.ProcessInstruction(fixture.Input.Data, instrAccts, []uint64{0})

		instrCode := instrCodeFromFixtureInstrData(fixture)

		if instrCode == -1 || instrCode == 1769234798 || instrCode == 1613178663 || instrCode == 399877894 || instrCode == 14 {
			continue
		}

		testcaseCounter++

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

func TestConformance_Vote_Program_Single_Testcase(t *testing.T) {
	basePath := "test-vectors/instr/fixtures/vote"
	fn := "c7a76529c4a192ee3e6f79571308e85d0c53ba77.fix"

	fname := fmt.Sprintf("%s/%s", basePath, fn)

	in, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatalln("Error reading file:", err)
	}

	fixture := &InstrFixture{}
	if err := proto.Unmarshal(in, fixture); err != nil {
		log.Fatalln("Failed to parse fixture:", err)
	}

	fmt.Printf("testcase file: %s\n", fname)

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
