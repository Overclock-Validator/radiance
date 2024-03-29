package sealevel

import "errors"

var (
	ErrCopyOverlapping    = errors.New("Overlapping copy")
	TooManySlices         = errors.New("Hashing too many sequences")
	InvalidLength         = errors.New("InvalidLength")
	InvalidString         = errors.New("InvalidString")
	MaxSeedLengthExceeded = errors.New("MaxSeedLengthExceeded")
	ReturnDataTooLarge    = errors.New("ReturnDataTooLarge")
	InvalidArgument       = errors.New("InvalidArgument")
	NotEnoughAccountKeys  = errors.New("NotEnoughAccountKeys")
	TooManySigners        = errors.New("TooManySigners")
	TooManyBytesConsumed  = errors.New("TooManyBytesConsumed")
	MalformedBool         = errors.New("MalformedBool")
)
