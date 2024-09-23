package replay

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.firedancer.io/radiance/fixtures"
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

type testAcct struct {
	Lamports   string `json:"lamports"`
	Len        uint64 `json:"data.len"`
	Owner      string `json:"owner"`
	Executable bool   `json:"executable"`
	RentEpoch  string `json:"rent_epoch"`
	Data       string `json:"data"`
	Pubkey     string `json:"pubkey"`
}

func Test_Accounts_Delta_Hash(t *testing.T) {
	acctsJson := fixtures.Load(t, "hash", "accts.json")

	var testAccts []testAcct
	err := json.Unmarshal(acctsJson, &testAccts)
	if err != nil {
		panic(fmt.Sprintf("unable to unmarshal json: %s\n", err))
	}

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

	fmt.Printf("%+v\n\n", accts[1])

	acctsDeltaHash := calculateAcctsDeltaHash(accts)
	knownCorrectAcctsDeltaHash := []byte{159, 193, 234, 234, 232, 60, 116, 92, 110, 95, 206, 137, 221, 188, 150, 211, 233, 2, 24, 56, 20, 207, 125, 123, 135, 193, 5, 37, 114, 203, 108, 109}

	fmt.Printf("calculated accts delta hash: %d\n", acctsDeltaHash)
	fmt.Printf("known accts delta hash: %d\n", knownCorrectAcctsDeltaHash)

	assert.Equal(t, acctsDeltaHash, knownCorrectAcctsDeltaHash)
}
