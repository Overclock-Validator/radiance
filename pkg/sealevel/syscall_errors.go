package sealevel

import "errors"

var (
	ErrCopyOverlapping    = errors.New("Overlapping copy")
	TooManySlices         = errors.New("Hashing too many sequences")
	InvalidLength         = errors.New("InvalidLength")
	InvalidString         = errors.New("InvalidString")
	MaxSeedLengthExceeded = errors.New("MaxSeedLengthExceeded")
	ReturnDataTooLarge    = errors.New("ReturnDataTooLarge")
)
