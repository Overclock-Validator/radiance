package cu

import "errors"

// This file contains helper routines for the calculation of compute units.

var ComputeExceeded = errors.New("Compute exceeded")

func ConsumeLowerBound(cu int, lower int, x int) int {
	if x < lower {
		return cu - lower
	}
	return cu - x
}

func ConsumeComputeMeter(cu int, cost int) (int, error) {
	cuNew := cu - cost
	if cuNew < 0 {
		return -1, ComputeExceeded
	}
	return cuNew, nil
}
