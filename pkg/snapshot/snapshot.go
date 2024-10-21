package snapshot

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"

	"sync/atomic"
	"time"

	"github.com/Overclock-Validator/sniper"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/klauspost/compress/zstd"
	"github.com/panjf2000/ants/v2"
	"go.firedancer.io/radiance/pkg/accountsdb"
)

func UnmarshalManifestFromSnapshot(filename string, accountsDbDir string) (*SnapshotManifest, error) {
	manifest := new(SnapshotManifest)

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	manifestOutputFile := fmt.Sprintf("%s/manifest", accountsDbDir)
	if err = os.MkdirAll(accountsDbDir, 0775); err != nil {
		return nil, err
	}
	manifestOut, err := os.Create(manifestOutputFile)
	if err != nil {
		return nil, err
	}
	defer manifestOut.Close()

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
				_, err = io.Copy(manifestOut, bytes.NewBuffer(writer.Bytes()))
				if err != nil {
					fmt.Printf("err copying manifest file out: %s\n", err)
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

type appendVecCopyingTask struct {
	Filename  string
	TarBuffer *bytes.Buffer
}

type indexEntryBuilderTask struct {
	Data     []byte
	FileSize uint64
	Slot     uint64
	FileId   uint64
}

type indexEntryCommitterTask struct {
	IndexEntries []*accountsdb.AccountIndexEntry
	Pubkeys      []solana.PublicKey
}

func BuildAccountsIndexFromSnapshot(snapshotFile string, accountsDbDir string) error {
	manifest, err := UnmarshalManifestFromSnapshot(snapshotFile, accountsDbDir)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		return err
	}

	file, err := os.Open(snapshotFile)
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

	start := time.Now()

	appendVecsOutputDir := fmt.Sprintf("%s/accounts", accountsDbDir)
	if err = os.MkdirAll(appendVecsOutputDir, 0775); err != nil {
		return err
	}

	indexOutputDir := fmt.Sprintf("%s/index", accountsDbDir)
	if err = os.MkdirAll(indexOutputDir, 0775); err != nil {
		return err
	}

	db, err := sniper.Open(sniper.Dir(indexOutputDir), sniper.ChunksCollision(32))
	if err != nil {
		fmt.Printf("failed to open database: %s\n", err)
		return err
	}
	defer db.Close()

	defer ants.Release()

	//var numEntriesCommitted atomic.Uint64
	//var numTimesAppendVecCopyingPoolCalled atomic.Uint64
	//var numTimesIndexEntryBuilderPool atomic.Uint64
	//var numTimesIndexEntryCommiterPool atomic.Uint64

	var largestFileId atomic.Uint64

	wg := sync.WaitGroup{}

	indexEntryCommiterPool, _ := ants.NewPoolWithFunc(500, func(i interface{}) {
		defer wg.Done()
		//numTimesIndexEntryCommiterPool.Add(1)

		task := i.(indexEntryCommitterTask)

		writer := new(bytes.Buffer)

		for idx, entry := range task.IndexEntries {
			writer.Reset()
			encoder := bin.NewBinEncoder(writer)

			err = entry.MarshalWithEncoder(encoder)
			if err != nil {
				fmt.Printf("failed to encode index entry: %s\n", err)
				return
			}

			err = db.SetIfSlotHigher(task.Pubkeys[idx][:], writer.Bytes(), 0)
			if err != nil {
				fmt.Printf("error calling SetIfHigherSlot for %s: %s\n", task.Pubkeys[idx], err)
			}
			//numEntriesCommitted.Add(1)
		}
	})

	indexEntryBuilderPool, _ := ants.NewPoolWithFunc(500, func(i interface{}) {
		defer wg.Done()
		//numTimesIndexEntryBuilderPool.Add(1)

		task := i.(indexEntryBuilderTask)
		pubkeys, entries, err := accountsdb.BuildIndexEntriesFromAppendVecs(task.Data, task.FileSize, task.Slot, task.FileId)
		if err != nil {
			fmt.Printf("%s\n", err)
			return
		}

		commitTask := indexEntryCommitterTask{IndexEntries: entries, Pubkeys: pubkeys}
		wg.Add(1)
		err = indexEntryCommiterPool.Invoke(commitTask)
		if err != nil {
			fmt.Printf("error calling indexEntryCommiterPool.Invoke\n")
		}
	})

	appendVecCopyingPool, _ := ants.NewPoolWithFunc(500, func(i interface{}) {
		defer wg.Done()
		//numTimesAppendVecCopyingPoolCalled.Add(1)

		task := i.(appendVecCopyingTask)
		filename := task.Filename
		writer := task.TarBuffer

		// identify appendvec files, whose path is of the form "accounts/SLOT.ID"
		if strings.Contains(filename, "accounts/") {
			if !strings.Contains(filename, ".") {
				return
			}

			outFile, err := os.Create(fmt.Sprintf("%s/%s", accountsDbDir, filename))
			if err != nil {
				fmt.Printf("err creating new: %s\n", err)
				return
			}

			appendVecBytes := writer.Bytes()

			_, err = io.Copy(outFile, bytes.NewReader(appendVecBytes))
			if err != nil {
				fmt.Printf("err copying file out: %s\n", err)
				return
			}

			// parse slot and file ID out of filename
			_, after, found := strings.Cut(filename, "/")
			if !found {
				panic(fmt.Sprintf("invalid appendvec path format: %s", filename))
			}

			slotStr, idStr, found := strings.Cut(after, ".")
			slot, err := strconv.ParseUint(slotStr, 10, 64)
			if err != nil {
				fmt.Printf("invalid snapshot - unable to convert string to slot\n")
				panic("")
			}

			fileId, err := strconv.ParseUint(idStr, 10, 64)
			if err != nil {
				panic("invalid snapshot - unable to convert string to file id\n")
			}

			if fileId > largestFileId.Load() {
				largestFileId.Store(fileId)
			}

			// find the relevant appendvec storage info
			var fileSize uint64
			for _, av := range manifest.AccountsDb.Storages[slot].AcctVecs {
				if av.Id == fileId {
					fileSize = av.FileSize
					break
				}
			}

			if fileSize == 0 {
				panic("programming error - fileSize for appendvec was 0")
			}

			task := indexEntryBuilderTask{Data: appendVecBytes, FileSize: fileSize, Slot: slot, FileId: fileId}

			wg.Add(1)
			err = indexEntryBuilderPool.Invoke(task)
			if err != nil {
				fmt.Printf("error calling indexEntryBuilderPool.Invoke\n")
			}
		}
	})

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Printf("err reading next tar: %s\n", err)
			return err
		}

		writer := new(bytes.Buffer)
		_, err = io.Copy(writer, tarReader)
		if err != nil {
			fmt.Printf("err copying data to reader: %s\n", err)
			return err
		}

		task := appendVecCopyingTask{TarBuffer: writer, Filename: header.Name}
		wg.Add(1)
		err = appendVecCopyingPool.Invoke(task)
		if err != nil {
			fmt.Printf("error calling appendVecCopyingPool.Invoke\n")
		}
	}

	fmt.Printf("done in %s. waiting for all tasks to complete.\n", time.Since(start))

	wg.Wait()

	//fmt.Printf("accts processed: %d, in %s. numTimesAppendVecCopyingPoolCalled: %d, numTimesIndexEntryBuilderPool: %d, numTimesIndexEntryCommiterPool: %d\n", numEntriesCommitted.Load(), time.Since(start), numTimesAppendVecCopyingPoolCalled.Load(), numTimesIndexEntryBuilderPool.Load(), numTimesIndexEntryCommiterPool.Load())

	fmt.Printf("snapshot processed in %s.\n", time.Since(start))

	largestFileIdFile, err := os.Create(fmt.Sprintf("%s/largest_file_id", accountsDbDir))
	if err != nil {
		fmt.Printf("err creating new: %s\n", err)
		return err
	}

	largestFileIdBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(largestFileIdBytes, largestFileId.Load())

	numBytesWritten, err := largestFileIdFile.Write(largestFileIdBytes[:])
	if err != nil {
		fmt.Printf("error writing largest file ID to file: %s\n", err)
		return err
	} else if numBytesWritten != 8 {
		fmt.Printf("error writing largest file ID to file\n")
		return fmt.Errorf("error writing largest file ID to file, wrote %d bytes", numBytesWritten)
	}

	largestFileIdFile.Close()

	bankHashOutputFileName := fmt.Sprintf("%s/bank_hash", accountsDbDir)
	bankHashFile, err := os.Create(bankHashOutputFileName)
	if err != nil {
		fmt.Printf("err creating new: %s\n", err)
		return err
	}

	numBytesWritten, err = bankHashFile.Write(manifest.Bank.Hash[:])
	if err != nil {
		fmt.Printf("error writing bank hash to file: %s\n", err)
		return err
	} else if numBytesWritten != 32 {
		fmt.Printf("error writing bank hash to file\n")
		return fmt.Errorf("error writing bank hash to file, wrote %d bytes", numBytesWritten)
	}

	bankHashFile.Close()

	return nil
}

func LoadManifestFromFile(filename string) (*SnapshotManifest, error) {
	manifestFile, err := os.Open(filename)
	if err != nil {
		fmt.Printf("failed to open %s\n", filename)
		return nil, err
	}
	manifestBytes, err := ioutil.ReadAll(manifestFile)
	if err != nil {
		return nil, err
	}

	manifest := new(SnapshotManifest)
	decoder := bin.NewBinDecoder(manifestBytes)
	err = manifest.UnmarshalWithDecoder(decoder)
	if err != nil {
		return nil, err
	}

	return manifest, nil
}
