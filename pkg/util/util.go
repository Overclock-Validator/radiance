package util

import (
	"encoding/binary"
	"regexp"
	"runtime"
	"slices"
	"sort"

	"github.com/gagliardetto/solana-go"
	"github.com/zeebo/blake3"
	"go.firedancer.io/radiance/pkg/accounts"
	"k8s.io/klog/v2"
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

func PubkeyCmp(a solana.PublicKey, b solana.PublicKey) bool {
	for i := uint64(0); i < 4; i++ {
		a1 := binary.BigEndian.Uint64(a[8*i:])
		b1 := binary.BigEndian.Uint64(b[8*i:])
		if a1 != b1 {
			return a1 < b1
		}
	}
	return false
}

func DedupePubkeys(pubkeys []solana.PublicKey) []solana.PublicKey {
	sort.SliceStable(pubkeys, func(i, j int) bool {
		return PubkeyCmp(pubkeys[i], pubkeys[j])
	})

	sortedPubkeys := slices.Compact(pubkeys)
	return sortedPubkeys
}

func CalculateAcctHash(acct accounts.Account) []byte {
	hasher := blake3.New()

	var lamportBytes [8]byte
	binary.LittleEndian.PutUint64(lamportBytes[:], acct.Lamports)
	_, _ = hasher.Write(lamportBytes[:])

	var rentEpochBytes [8]byte
	binary.LittleEndian.PutUint64(rentEpochBytes[:], acct.RentEpoch)
	_, _ = hasher.Write(rentEpochBytes[:])

	_, _ = hasher.Write(acct.Data)

	if acct.Executable {
		_, _ = hasher.Write([]byte{1})
	} else {
		_, _ = hasher.Write([]byte{0})
	}

	_, _ = hasher.Write(acct.Owner[:])
	_, _ = hasher.Write(acct.Key[:])

	return hasher.Sum(nil)
}

// this logs the function name as well.
func VerboseHandleError(err error) (b bool) {
	if err != nil {
		pc, filename, line, _ := runtime.Caller(1)

		klog.Infof("[error] in %s[%s:%d] %v", runtime.FuncForPC(pc).Name(), filename, line, err)
		b = true
	}
	return
}
