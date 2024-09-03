package snapshot

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	bin "github.com/gagliardetto/binary"
	"github.com/klauspost/compress/zstd"
	"go.firedancer.io/radiance/pkg/accounts"
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

func LoadAccountsToAccountsDbFromSnapshot(filename string, accountsDb accounts.Accounts) error {
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

	var numAcctsProcessed uint64
	start := time.Now()

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		// identify appendvec files, whose path is of the form "accounts/SLOT.ID"
		if strings.Contains(header.Name, "accounts/") {
			if !strings.Contains(header.Name, ".") {
				continue
			}

			writer := new(bytes.Buffer)
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

			// add accounts to accounts db
			for _, a := range accts {
				numAcctsProcessed++

				var k [32]byte
				copy(k[:], a.Key[:])

				// if an account for this pubkey already exists in the accounts db, only go ahead and add
				// this entry we have here if the existing entry's slot is lower (older).
				slotForExistingAcct, err := accountsDb.(accounts.PersistentAccountsDb).SlotForAcct(&k)
				if err == nil && slotForExistingAcct > slot {
					//fmt.Printf("skipped dupe %s. slotForExistingAcct = %d, current slot = %d\n", a.Key, slotForExistingAcct, slot)
					continue
				}

				(*a).Slot = slot
				err = accountsDb.SetAccount(&k, a)
				if err != nil {
					fmt.Printf("error adding acct %s to accounts db: %s\n", a.Key, err)
					return err
				}

				//fmt.Printf("added account to acctsdb (# %d)\n", numAcctsProcessed)

				if (numAcctsProcessed % 50000000) == 0 {
					fmt.Printf("accts processed: %d, in %s\n", numAcctsProcessed, time.Since(start))
				}
			}
		}
	}

	fmt.Printf("accts processed: %d, in %s\n", numAcctsProcessed, time.Since(start))
	return nil
}
