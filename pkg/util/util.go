package util

import (
	"regexp"
)

// Got to be a valid hostname as per Let's Encrypt, ie 'localhost' is not valid.
// For more info, read https://letsencrypt.org/docs/certificates-for-localhost/.
var validHostnameRegexp = regexp.MustCompile(`^(?i)[a-z0-9-]+(\.[a-z0-9-]+)+\.?$`)

// IsValidHostname returns true if the hostname is valid.
//
// It uses a simple regular expression to check the hostname validity.
func IsValidHostname(hostname string) bool {
	return validHostnameRegexp.MatchString(hostname)
}

func AlignUp(unaligned uint64, align uint64) uint64 {
	mask := align - 1
	alignedVal := unaligned + (-unaligned & mask)
	return alignedVal
}
