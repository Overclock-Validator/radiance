package sealevel

func isNonOverlapping(src, srcLen, dst, dstLen uint64) bool {
	if src > dst {
		return src-dst >= dstLen
	} else {
		return dst-src >= srcLen
	}
}
