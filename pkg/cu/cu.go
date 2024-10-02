package cu

import (
	"errors"

	"go.firedancer.io/radiance/pkg/safemath"
)

var ErrComputeExceeded = errors.New("Compute exceeded")

type ComputeMeter struct {
	computeMeter    uint64
	startingBalance uint64
	exceeded        bool
}

func NewComputeMeter(budget uint64) ComputeMeter {
	return ComputeMeter{computeMeter: budget, startingBalance: budget}
}

func NewComputeMeterDefault() ComputeMeter {
	return ComputeMeter{computeMeter: 200000, startingBalance: 200000}
}

func (cm *ComputeMeter) Consume(cost uint64) error {
	cm.exceeded = cm.computeMeter < cost
	cm.computeMeter = safemath.SaturatingSubU64(cm.computeMeter, cost)

	if cm.exceeded {
		return ErrComputeExceeded
	}

	return nil
}

func (cm *ComputeMeter) Used() uint64 {
	return cm.startingBalance - cm.computeMeter
}

func (cm *ComputeMeter) Exceeded() bool {
	return cm.exceeded
}

func (cm *ComputeMeter) Remaining() uint64 {
	return cm.computeMeter
}
