package accounts

import bin "github.com/gagliardetto/binary"

type AccountIndexEntry struct {
	Slot   uint64
	FileId uint64
	Offset uint64
}

func (entry *AccountIndexEntry) MarshalWithEncoder(encoder *bin.Encoder) error {
	var err error

	err = encoder.WriteUint64(entry.Slot, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(entry.FileId, bin.LE)
	if err != nil {
		return err
	}

	err = encoder.WriteUint64(entry.Offset, bin.LE)
	return err
}
