package replay

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.firedancer.io/radiance/pkg/accounts"
	"go.firedancer.io/radiance/pkg/base58"
)

// uses known good values to test if bankhash computes correctly
func Test_Compute_Bank_Hash(t *testing.T) {
	acctsDeltaHash := []byte{148, 1, 99, 1, 94, 42, 27, 37, 216, 66, 0, 57, 116, 109, 251, 51, 250, 101, 228, 74, 44, 3, 94, 73, 120, 148, 27, 210, 78, 34, 112, 212}
	parentBankHash := [32]byte{216, 24, 141, 114, 110, 72, 188, 246, 47, 80, 102, 40, 122, 219, 11, 94, 100, 159, 96, 122, 195, 101, 140, 19, 22, 225, 243, 127, 23, 182, 65, 90}
	numSigs := uint64(2)
	blockHash := [32]byte{113, 124, 28, 34, 197, 214, 189, 118, 67, 41, 212, 2, 122, 6, 74, 59, 124, 160, 185, 122, 37, 39, 142, 149, 224, 42, 26, 49, 215, 200, 16, 19}

	// correct bankhash for the above values
	knownCorrectBankHash := []byte{190, 156, 54, 163, 252, 183, 243, 10, 147, 168, 42, 47, 214, 172, 160, 64, 86, 32, 203, 54, 119, 230, 201, 36, 164, 27, 30, 244, 96, 202, 88, 154}

	bankHash := calculateBankHash(acctsDeltaHash, parentBankHash, numSigs, blockHash)
	assert.Equal(t, bankHash, knownCorrectBankHash)
}

func Test_Accounts_Delta_Hash(t *testing.T) {

	data1, err := hex.DecodeString("010040000000000000ffffdffffffffffefffffffffffff7fffffffffffffffffffffffffffffefffbfd7f000000000000000000000000000000000000000000")
	assert.NoError(t, err)
	acct1 := accounts.Account{Lamports: 913326000, Owner: base58.MustDecodeFromString("Sysvar1111111111111111111111111111111111111"), Executable: false,
		RentEpoch: 0, Data: data1, Key: base58.MustDecodeFromString("SysvarS1otHistory11111111111111111111111111")}

	acct2 := accounts.Account{Lamports: 499998715000, Owner: base58.MustDecodeFromString("11111111111111111111111111111111"), Executable: false, RentEpoch: 18446744073709551615, Key: base58.MustDecodeFromString("49EaB72ejufhYAdTVE9GKrQrcCAKyrxvaWS8NSNDfbt1")}

	data3, err := hex.DecodeString("08010000000000000d01000000000000d8188d726e48bcf62f5066287adb0b5e649f607ac3658c1316e1f37f17b6415a0c01000000000000c9297fdfd1a4679c")
	assert.NoError(t, err)
	acct3 := accounts.Account{Lamports: 143487360, Owner: base58.MustDecodeFromString("Sysvar1111111111111111111111111111111111111"), Executable: false, RentEpoch: 0, Data: data3, Key: base58.MustDecodeFromString("SysvarS1otHashes111111111111111111111111111")}

	data4, err := hex.DecodeString("020000002eaf0d99aa7260c32313655024147d6eb4fc58bc2cca30c8c4eb8d67c2b424e6f65707763d35460526811ef777a9c246be0c0129bd80c43ec201fed5")
	assert.NoError(t, err)
	acct4 := accounts.Account{Lamports: 1000000000000000, Owner: base58.MustDecodeFromString("Vote111111111111111111111111111111111111111"), Executable: false, RentEpoch: 18446744073709551615, Data: data4, Key: base58.MustDecodeFromString("HacGEcrPNhjNUUib432H2aYaGWeZwjFkgHSREE6D8AyB")}

	data5, err := hex.DecodeString("0e010000000000004bfaf066000000000000000000000000010000000000000059fbf06600000000")
	assert.NoError(t, err)
	acct5 := accounts.Account{Lamports: 1169280, Owner: base58.MustDecodeFromString("Sysvar1111111111111111111111111111111111111"), Executable: false, RentEpoch: 0, Data: data5, Key: base58.MustDecodeFromString("SysvarC1ock11111111111111111111111111111111")}

	data6, err := hex.DecodeString("9600000000000000717c1c22c5d6bd764329d4027a064a3b7ca0b97a25278e95e02a1a31d7c810138813000000000000afa8a43eb41a93e68bc82a3009293818")
	assert.NoError(t, err)
	acct6 := accounts.Account{Lamports: 42706560, Owner: base58.MustDecodeFromString("Sysvar1111111111111111111111111111111111111"), Executable: false, RentEpoch: 0, Data: data6, Key: base58.MustDecodeFromString("SysvarRecentB1ockHashes11111111111111111111")}

	accts := []*accounts.Account{&acct1, &acct2, &acct3, &acct4, &acct5, &acct6}

	acctsDeltaHash := calculateAcctsDeltaHash(accts)
	knownCorrectAcctsDeltaHash := []byte{148, 1, 99, 1, 94, 42, 27, 37, 216, 66, 0, 57, 116, 109, 251, 51, 250, 101, 228, 74, 44, 3, 94, 73, 120, 148, 27, 210, 78, 34, 112, 212}

	fmt.Printf("calculated accts delta hash: %d\n", acctsDeltaHash)
	fmt.Printf("known accts delta hash: %d\n", knownCorrectAcctsDeltaHash)

	//assert.Equal(t, knownCorrectAcctsDeltaHash, acctsDeltaHash)
}
