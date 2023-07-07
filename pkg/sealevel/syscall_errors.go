package sealevel

import "errors"

var (
	ErrCopyOverlapping = errors.New("Overlapping copy")
	TooManySlices      = errors.New("Hashing too many sequences")
)
