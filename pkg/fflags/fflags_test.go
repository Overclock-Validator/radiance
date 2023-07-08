package fflags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.firedancer.io/radiance/pkg/solana"
)

// The TestFflags_WithFeature_And_WithoutFeature function tests that the
// WithFeature and WithoutFeature APIs correctly enable and disable a feature
// as expected.
func TestFflags_WithFeature_And_WithoutFeature(t *testing.T) {
	var SomeFeature = Register(solana.MustAddress("16FMCmgLzCNNz6eTwGanbyN2ZxvTBSLuQ6DZhgeMshg"), "SomeFeature")
	var f Features

	f.WithFeature(SomeFeature)
	assert.Equal(t, f.HasFeature(SomeFeature), true)

	f.WithoutFeature(SomeFeature)
	assert.Equal(t, f.HasFeature(SomeFeature), false)

	f.WithFeature(SomeFeature)
	assert.Equal(t, f.HasFeature(SomeFeature), true)
}

// The TestFflags_ExpectPanicForUninitializedFeatureFlag function tests for
// HasFeature() panicking upon checking the status of a feature for which a
// bucket does not yet exist. The expected result is that this testcase panics.
// The reason for a deliberate panic upon calling HasFeature() for a feature
// that has not yet been allocated a bucket is so that developers are made
// aware that their code has not specifically enabled nor disabled a feature.
// This is ultimately intended to encourage clarity in the code as to whether
// a particular feature is enabled or disabled at any given time.
func TestFflags_ExpectPanicForUninitializedFeatureFlag(t *testing.T) {
	var SomeFeature = Register(solana.MustAddress("16FMCmgLzCNNz6eTwGanbyN2ZxvTBSLuQ6DZhgeMshg"), "SomeFeature")
	var f Features
	defer func() { _ = recover() }()
	_ = f.HasFeature(SomeFeature)
	t.Errorf("error - should have panicked due to feature flag not being either enabled via WithFeature() or disabled via WithoutFeature()")
}

// The TestFflags_ExpectPanicForInvalidFeatureFlag function tests for
// HasFeature() panicking on an invalid feature flag. The expected
// result in this test is a panic.
func TestFflags_ExpectPanicForInvalidFeatureFlag(t *testing.T) {
	var f Features
	defer func() { _ = recover() }()
	_ = f.HasFeature(1000)
	t.Errorf("error - should have panicked due to invalid feature flag")
}
