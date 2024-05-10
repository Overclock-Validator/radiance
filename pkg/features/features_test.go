package features

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The TestFflags_EnableAndDisable function tests that the
// enable and disable features work correctly.
func TestFflags_EnableAndDisable(t *testing.T) {
	f := NewFeaturesDefault()
	f.EnableFeature(StopTruncatingStringsInSyscalls, 0)
	assert.Equal(t, f.IsActive(StopTruncatingStringsInSyscalls), true)
	f.DisableFeature(StopTruncatingStringsInSyscalls)
	assert.Equal(t, f.IsActive(StopTruncatingStringsInSyscalls), false)
	f.EnableFeature(StopTruncatingStringsInSyscalls, 0)
	assert.Equal(t, f.IsActive(StopTruncatingStringsInSyscalls), true)
}

// The TestFflags_ListEnabled function tests that the AllEnabled function works
// as expected.
func TestFflags_ListEnabled(t *testing.T) {
	f := NewFeaturesDefault()
	f.EnableFeature(StopTruncatingStringsInSyscalls, 0)
	assert.Equal(t, f.AllEnabled(), []string{"feature StopTruncatingStringsInSyscalls (16FMCmgLzCNNz6eTwGanbyN2ZxvTBSLuQ6DZhgeMshg) enabled"})
}
