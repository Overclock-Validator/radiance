package replay

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/Overclock-Validator/mithril/fixtures"
	"github.com/Overclock-Validator/mithril/pkg/accounts"
	"github.com/Overclock-Validator/mithril/pkg/base58"
	"github.com/stretchr/testify/assert"
)

// uses known good values to test if bankhash computes correctly
func Test_Compute_Bank_Hash(t *testing.T) {
	acctsDeltaHash := []byte{148, 1, 99, 1, 94, 42, 27, 37, 216, 66, 0, 57, 116, 109, 251, 51, 250, 101, 228, 74, 44, 3, 94, 73, 120, 148, 27, 210, 78, 34, 112, 212}
	parentBankHash := [32]byte{216, 24, 141, 114, 110, 72, 188, 246, 47, 80, 102, 40, 122, 219, 11, 94, 100, 159, 96, 122, 195, 101, 140, 19, 22, 225, 243, 127, 23, 182, 65, 90}
	numSigs := uint64(2)
	blockHash := [32]byte{113, 124, 28, 34, 197, 214, 189, 118, 67, 41, 212, 2, 122, 6, 74, 59, 124, 160, 185, 122, 37, 39, 142, 149, 224, 42, 26, 49, 215, 200, 16, 19}

	// correct bankhash for the above values
	knownCorrectBankHash := []byte{190, 156, 54, 163, 252, 183, 243, 10, 147, 168, 42, 47, 214, 172, 160, 64, 86, 32, 203, 54, 119, 230, 201, 36, 164, 27, 30, 244, 96, 202, 88, 154}

	bankHash := calculateBankHash(nil, acctsDeltaHash, parentBankHash, numSigs, blockHash)
	assert.Equal(t, bankHash, knownCorrectBankHash)
}

type testAcct struct {
	Lamports   string `json:"lamports"`
	Len        uint64 `json:"data.len"`
	Owner      string `json:"owner"`
	Executable bool   `json:"executable"`
	RentEpoch  string `json:"rent_epoch"`
	Data       string `json:"data"`
	Pubkey     string `json:"pubkey"`
}

func Test_Accounts_Delta_Hash_And_BankHash(t *testing.T) {
	acctsJson := fixtures.Load(t, "hash", "accts.json")

	var testAccts []testAcct
	err := json.Unmarshal(acctsJson, &testAccts)
	assert.NoError(t, err)

	fmt.Printf("unmarshaled %d accts\n", len(testAccts))

	accts := make([]*accounts.Account, 0)
	for _, ta := range testAccts {
		data, err := hex.DecodeString(ta.Data)
		assert.NoError(t, err)
		lamports, err := strconv.ParseUint(ta.Lamports, 10, 64)
		rentEpoch, err := strconv.ParseUint(ta.RentEpoch, 10, 64)
		a := &accounts.Account{Key: base58.MustDecodeFromString(ta.Pubkey), Lamports: lamports, Data: data, Executable: ta.Executable, Owner: base58.MustDecodeFromString(ta.Owner), RentEpoch: rentEpoch}
		accts = append(accts, a)
	}

	acctsDeltaHash := calculateAcctsDeltaHash(accts)
	knownCorrectAcctsDeltaHash := []byte{159, 193, 234, 234, 232, 60, 116, 92, 110, 95, 206, 137, 221, 188, 150, 211, 233, 2, 24, 56, 20, 207, 125, 123, 135, 193, 5, 37, 114, 203, 108, 109}

	fmt.Printf("calculated accts delta hash: %d\n", acctsDeltaHash)
	fmt.Printf("known accts delta hash: %d\n", knownCorrectAcctsDeltaHash)

	assert.Equal(t, acctsDeltaHash, knownCorrectAcctsDeltaHash)

	parentBankHash := [32]byte{89, 9, 149, 199, 126, 19, 109, 42, 164, 143, 181, 134, 72, 50, 37, 12, 232, 164, 118, 184, 89, 104, 82, 205, 254, 58, 135, 223, 67, 69, 131, 62}
	numSigs := uint64(2)
	blockHash := [32]byte{146, 202, 69, 18, 36, 202, 121, 99, 47, 1, 177, 105, 158, 183, 91, 218, 104, 146, 24, 15, 17, 59, 160, 158, 71, 187, 255, 20, 105, 124, 226, 82}
	knownCorrectBankHash := []byte{119, 170, 167, 64, 81, 16, 52, 152, 70, 85, 198, 20, 1, 9, 69, 90, 128, 26, 216, 178, 224, 255, 106, 149, 70, 45, 52, 83, 69, 197, 64, 245}

	bankHash := calculateBankHash(nil, acctsDeltaHash, parentBankHash, numSigs, blockHash)

	fmt.Printf("calculated bankhash: %d\n", bankHash)
	fmt.Printf("known bankhash: %d\n", knownCorrectBankHash)

	assert.Equal(t, bankHash, knownCorrectBankHash)
}
