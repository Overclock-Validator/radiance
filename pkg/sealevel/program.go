package sealevel

type ValidatedProgram struct {
	LastUpdatedSlot uint64
	EntryPc         uint64
	TextCnt         uint64
	TextOffset      uint64
	RodataLen       uint64
}
