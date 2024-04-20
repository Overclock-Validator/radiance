package cu

import (
	"errors"

	"go.firedancer.io/radiance/pkg/safemath"
)

var ErrComputeExceeded = errors.New("Compute exceeded")

type ComputeMeter struct {
	computeMeter uint64
	exceeded     bool
}

func NewComputeMeter(budget uint64) ComputeMeter {
	return ComputeMeter{computeMeter: budget}
}

func NewComputeMeterDefault() ComputeMeter {
	return ComputeMeter{computeMeter: 10000}
}

func (cm *ComputeMeter) Consume(cost uint64) error {
	cm.exceeded = cm.computeMeter < cost
	cm.computeMeter = safemath.SaturatingSubU64(cm.computeMeter, cost)

	if cm.exceeded {
		return ErrComputeExceeded
	}

	return nil
}

func (cm *ComputeMeter) Remaining() uint64 {
	return cm.computeMeter
}

func (cm *ComputeMeter) Exceeded() bool {
	return cm.exceeded
}
