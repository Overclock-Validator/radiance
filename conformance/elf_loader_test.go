package conformance

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.firedancer.io/radiance/pkg/sbpf/loader"
	"google.golang.org/protobuf/proto"
)

func decompressFixture(compressedBytes []byte) ([]byte, error) {
	readerBuf := bytes.NewReader(compressedBytes)
	reader, err := zstd.NewReader(readerBuf)
	if err != nil {
		return nil, err
	}

	var decompressedBytes bytes.Buffer
	decompressedWriter := bufio.NewWriter(&decompressedBytes)
	_, err = io.Copy(decompressedWriter, reader)
	if err != nil {
		return nil, err
	}

	return decompressedBytes.Bytes(), nil
}

func TestConformance_Elf_Loader(t *testing.T) {
	basePath := "test-vectors/elf_loader/fixtures"
	fileInfos, err := ioutil.ReadDir(basePath)
	assert.NoError(t, err)

	failedTestcases := make([]string, 0)

	var fnames []string
	for _, fileInfo := range fileInfos {

		fmt.Printf("filename: %s\n", fileInfo.Name())
		if !strings.HasSuffix(fileInfo.Name(), ".fix.zst") {
			continue
		}

		filePath := fmt.Sprintf("%s/%s", basePath, fileInfo.Name())
		fnames = append(fnames, filePath)
	}

	for _, fn := range fnames {
		in, err := ioutil.ReadFile(fn)
		if err != nil {
			log.Fatalln("Error reading file:", err)
		}

		decompressedFixture, err := decompressFixture(in)
		if err != nil {
			log.Fatalln("unable to decompress fixture")
		}

		fixture := &ELFLoaderFixture{}
		if err := proto.Unmarshal(decompressedFixture, fixture); err != nil {
			//fmt.Printf("Failed to parse fixture: %s\n", err)
			continue
		}

		// no input? skip..
		if fixture.Input == nil {
			continue
		}

		loader, err := loader.NewLoaderFromBytes(fixture.Input.Elf.Data)
		require.NoError(t, err)
		require.NotNil(t, loader)

		_, err = loader.Load()

		fmt.Printf("\n")

		if fixture.Output != nil && err == nil {
			fmt.Printf("******** SUCCESS: testcase %s loaded successfully, and fixture also indicated successful load\n", fn)
		} else if fixture.Output == nil && err != nil {
			fmt.Printf("******** SUCCESS: testcase %s failed to load (%s), and fixture also indicated failure to load\n", fn, err)
		} else if fixture.Output == nil && err == nil {
			fmt.Printf("******** FAILURE [1]: testcase %s loaded successfully but fixture indicated failure to load\n", fn)
			failedTestcases = append(failedTestcases, fn)
		} else if fixture.Output != nil && err != nil {
			fmt.Printf("******** FAILURE [2]: fixture indicates success, but loader returned an error: %s\n", err)
			failedTestcases = append(failedTestcases, fn)
		} else {
			panic("is this even possible??")
		}
	}

	fmt.Printf("\n\nfailed testcases %d / %d:\n", len(failedTestcases), len(fnames))
}

func TestConformance_Elf_Loader_Single_Testcase(t *testing.T) {
	basePath := "test-vectors/elf_loader/fixtures"
	fn := "b40170a6c947d285bd6d07cccbad5776.00057928.honggfuzz.fix.zst"

	fname := fmt.Sprintf("%s/%s", basePath, fn)

	in, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatalln("Error reading file:", err)
	}

	decompressedFixture, err := decompressFixture(in)
	if err != nil {
		log.Fatalln("unable to decompress fixture")
	}

	fixture := &ELFLoaderFixture{}
	if err := proto.Unmarshal(decompressedFixture, fixture); err != nil {
		log.Fatalln("Failed to parse fixture:", err)
	}

	fmt.Printf("successfully deserialized elf fixture\n")

	fmt.Printf("len of ELF program: %d vs. reported size %d\n", len(fixture.Input.Elf.Data), fixture.Input.ElfSz)
	fmt.Printf("EntryPc: %d\n", fixture.Output.EntryPc)

	loader, err := loader.NewLoaderFromBytes(fixture.Input.Elf.Data)
	require.NoError(t, err)
	require.NotNil(t, loader)

	program, err := loader.Load()
	require.NoError(t, err)
	require.NotNil(t, program)

	err = program.Verify()
	require.NoError(t, err)

	require.Equal(t, fixture.Output.EntryPc, program.Entrypoint)

	fmt.Printf("fixture call dests:\n")
	for _, callDst := range fixture.Output.Calldests {
		fmt.Printf("%d\n", callDst)
	}

	// get call dests into a slice
	callDests := make([]uint64, 0)
	for _, entry := range program.Funcs {
		callDests = append(callDests, uint64(entry))
	}

	fmt.Printf("\nmithril call dests:\n")
	for _, callDst := range program.Funcs {
		fmt.Printf("%d\n", callDst)
	}

	//EntryPc
	//Rodata
	//RodataSz
	//TextCnt
	//TextOff

	/*type Program struct {
		RO         []byte // read-only segment containing text and ELFs
		Text       []byte
		TextVA     uint64
		Entrypoint uint64 // PC
		Funcs      map[uint32]int64
	}*/
}
