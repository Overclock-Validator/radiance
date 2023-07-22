// Package fflags manages Solana protocol features.
//
// The feature mechanism coordinates the activation of (breaking)
// changes to the Solana protocol.
package fflags

import (
	"go.firedancer.io/radiance/pkg/solana"
)

// Feature is an opaque handle to a feature flag.
type Feature uint

type featureInfo struct {
	handle Feature
	name   string
	gate   solana.Address
}

// seq is the sequence number of allocating feature flag IDs.
// Zero is the sentinel value.
var seq Feature

// featureMap maps feature handle numbers to feature gate addresses.
var featureMap = make(map[Feature]featureInfo)

// Register creates a new application-wide feature flag for the given
// feature gate address. Returns an opaque handle number. Idempotent,
// such that the same gate address can be registered twice.
// Not thread-safe -- should be only called from the init/main goroutine.
func Register(gate solana.Address, name string) Feature {
	seq++
	s := seq
	if info, ok := featureMap[s]; ok {
		return info.handle
	}
	featureMap[s] = featureInfo{
		handle: s,
		name:   name,
		gate:   gate,
	}
	return s
}

var buckets []uint32

func set(idx uint, v uint) {
	if idx == 0 || idx > uint(seq) {
		panic("invalid feature flag handle")
	}
	bucket := int(idx / 32)
	if bucket >= len(buckets) {
		buckets = append(buckets, make([]uint32, bucket-len(buckets)+1)...)
	}
	if v == 1 {
		buckets[bucket] |= 1 << idx
	} else if v == 0 {
		buckets[bucket] &= ^(1 << idx)
	} else {
		panic("invalid bit value; valid values are 0 and 1")
	}
}

// HasFeature returns true if the given feature flag is set.
// Panics on invalid handle, or if the expected bucket for the given feature
// has not yet been created (via enablement using WithFeature or disablement
// using WithoutFeature).
func HasFeature(flag Feature) bool {
	bucket := uint(flag) / 32
	if flag == 0 || flag > seq {
		panic("invalid feature flag handle")
	} else if int(bucket) >= len(buckets) {
		panic("no bucket for feature: missing WithFeature or WithoutFeature.")
	}
	return buckets[bucket]&(1<<(uint(flag))) != 0
}

// WithFeature enables the corresponding feature application-wide.
// Panics on invalid handle.
func WithFeature(flag Feature) {
	set(uint(flag), 1)
}

// WithoutFeature disables the corresponding feature application-wide.
func WithoutFeature(flag Feature) {
	set(uint(flag), 0)
}
