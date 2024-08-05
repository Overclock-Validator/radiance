package conformance

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.firedancer.io/radiance/pkg/sealevel"
)

func TestConformance_Poseidon_Big_Endian(t *testing.T) {
	bytes1 := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

	bytes2 := []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}

	expected1 := []byte{13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94,
		3, 85, 242, 99, 25, 32, 123, 132, 254, 156, 162,
		206, 27, 38, 231, 53, 200, 41, 130, 25, 144}

	hash, err := sealevel.PoseidonHash([][]byte{bytes1, bytes2}, true)
	assert.NoError(t, err)
	assert.Equal(t, expected1, hash)

	input3 := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	}

	expected2 := []byte{
		0, 122, 243, 70, 226, 211, 4, 39, 158, 121, 224,
		169, 243, 2, 63, 119, 18, 148, 167, 138, 203, 112,
		231, 63, 144, 175, 226, 124, 173, 64, 30, 129}

	hash, err = sealevel.PoseidonHash([][]byte{input3, input3}, true)
	assert.NoError(t, err)
	assert.Equal(t, expected2, hash)

	expected3 := []byte{
		2, 192, 6, 110, 16, 167, 42, 189, 43, 51, 195,
		178, 20, 203, 62, 129, 188, 177, 182, 227, 9, 97,
		205, 35, 194, 2, 177, 134, 115, 191, 37, 67,
	}

	hash, err = sealevel.PoseidonHash([][]byte{input3, input3, input3}, true)
	assert.NoError(t, err)
	assert.Equal(t, expected3, hash)
}

func TestConformance_Poseidon_Little_Endian(t *testing.T) {
	bytes1 := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

	bytes2 := []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}

	expected := []byte{144, 25, 130, 41, 200, 53, 231, 38, 27, 206, 162,
		156, 254, 132, 123, 32, 25, 99, 242, 85, 3, 94,
		235, 125, 28, 140, 138, 143, 147, 225, 84, 13}

	hash, err := sealevel.PoseidonHash([][]byte{bytes1, bytes2}, false)
	assert.NoError(t, err)
	assert.Equal(t, expected, hash)
}
