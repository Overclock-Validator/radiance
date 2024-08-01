package conformance

import (
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestConformance_Precompile_Ed25519_Program(t *testing.T) {
	basePath := "test-vectors/precompile/fixtures/ed25519"
	fileInfos, err := ioutil.ReadDir(basePath)
	assert.NoError(t, err)

	var fnames []string
	for _, fileInfo := range fileInfos {
		filePath := fmt.Sprintf("%s/%s", basePath, fileInfo.Name())
		fnames = append(fnames, filePath)
	}

	failedTestcases := make([]string, 0)
	var testcaseCounter uint64

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

		if err == nil && fixture.Output.Result != 0 {
			failedTestcases = append(failedTestcases, fmt.Sprintf("failed testcase: %s. ed25519 returned success, but fixture reports %d\n", fname, fixture.Output.Result-1))
		} else if fixture.Output.Result == 0 && err != nil {
			failedTestcases = append(failedTestcases, fmt.Sprintf("failed testcase: %s. ed25519 returned success, but fixture reports %d\n", fname, fixture.Output.Result-1))
		}
	}

	fmt.Printf("\n\n")

	for _, fn := range failedTestcases {
		fmt.Printf("%s\n", fn)
	}

	hasFailedTestcases := len(failedTestcases) != 0

	for _, errMsg := range failedTestcases {
		fmt.Printf("%s\n", errMsg)
	}

	fmt.Printf("\n\nfailed testcases %d / %d:\n", len(failedTestcases), len(fnames))

	assert.Equal(t, false, hasFailedTestcases, "failing testcases found")
}
