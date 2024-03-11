package features

import "fmt"

type Features map[FeatureGate]bool

func NewFeaturesDefault() Features {
	return Features{}
}

func (f Features) EnableFeature(gate FeatureGate) Features {
	f[gate] = true
	return f
}

func (f Features) DisableFeature(gate FeatureGate) Features {
	f[gate] = false
	return f
}

func (f Features) IsActive(gate FeatureGate) bool {
	if enabled, found := f[gate]; found {
		return enabled
	} else {
		return false
	}
}

func (f Features) AllEnabled() []string {
	enabledFeatureStrs := make([]string, 0)
	for feat, enabled := range f {
		if enabled {
			enabledFeatureStrs = append(enabledFeatureStrs, fmt.Sprintf("feature %s (%s) enabled", feat.Name, feat.Address))
		}
	}
	return enabledFeatureStrs
}
