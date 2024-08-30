package snapshot

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	bin "github.com/gagliardetto/binary"
	"github.com/klauspost/compress/zstd"
)

func UnmarshalManifestFromSnapshot(filename string) (*SnapshotManifest, error) {
	manifest := new(SnapshotManifest)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	zstdReader, err := zstd.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer zstdReader.Close()

	tarReader := tar.NewReader(zstdReader)
	writer := new(bytes.Buffer)

	for {
		header, err := tarReader.Next()
		if err != nil {
			return nil, err
		}

		// identify manifest file, whose path is of the form "snapshots/SLOT/SLOT"
		if strings.Contains(header.Name, "snapshots/") {
			if strings.Count(header.Name, "/") == 2 {
				_, err := io.Copy(writer, tarReader)
				if err != nil {
					return nil, err
				}
				break
			}
		}
	}

	decoder := bin.NewBinDecoder(writer.Bytes())
	err = manifest.UnmarshalWithDecoder(decoder)

	return manifest, err
}

// TODO: store accounts to AccountsDB
// TODO: handle multiple versions of the same account key by using the one with the most recent slot number
func LoadAccountsFromSnapshot(filename string) error {
	manifest, err := UnmarshalManifestFromSnapshot(filename)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		return err
	}

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	zstdReader, err := zstd.NewReader(file)
	if err != nil {
		return err
	}
	defer zstdReader.Close()

	tarReader := tar.NewReader(zstdReader)
	writer := new(bytes.Buffer)

	for {
		header, err := tarReader.Next()
		if err != nil {
			return err
		}

		// identify appendvec files, whose path is of the form "accounts/SLOT.ID"
		if strings.Contains(header.Name, "accounts/") {
			if !strings.Contains(header.Name, ".") {
				continue
			}

			_, err := io.Copy(writer, tarReader)
			if err != nil {
				return err
			}

			// parse slot out of filename
			_, after, found := strings.Cut(header.Name, "/")
			if !found {
				panic(fmt.Sprintf("invalid appendvec path format: %s", header.Name))
			}

			slotStr, _, found := strings.Cut(after, ".")
			slot, err := strconv.ParseUint(slotStr, 10, 64)
			if err != nil {
				panic("invalid snapshot - unable to convert string to slot")
			}

			// find the relevant appendvec storage info
			appendVecInfo := manifest.AppendVecInfoForSlot(slot)
			if appendVecInfo == nil {
				panic(fmt.Sprintf("invalid snapshot - appendvec data for %s missing from manifest", header.Name))
			}

			accts, err := UnmarshalAccountsFromAppendVecs(writer.Bytes(), *appendVecInfo)
			if err != nil {
				fmt.Printf("error decoding append vecs: %s\n", err)
			}

			for _, a := range accts {
				fmt.Printf("acct: %+v\n", *a)
			}
		}
	}
}
