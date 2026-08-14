package slo

import (
	"math"

	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/model"
)

// EvaluateErrorRate evaluates an SLO from a normalized error rate. This path is
// used by the autonomous controller, where Prometheus commonly returns rates
// rather than integral good/total event counters.
func EvaluateErrorRate(target, errorRate float64) model.Budget {
	if target <= 0 || target >= 1 {
		return model.Budget{Target: target}
	}
	if errorRate < 0 {
		errorRate = 0
	}
	if errorRate > 1 {
		errorRate = 1
	}
	allowed := 1 - target
	burn := errorRate / allowed
	remaining := math.Max(0, 1-burn)
	return model.Budget{
		Target:            target,
		Observed:          1 - errorRate,
		AllowedBadEvents:  allowed,
		ActualBadEvents:   uint64(math.Round(errorRate * 1_000_000)),
		BurnMultiple:      round6(burn),
		RemainingFraction: round6(remaining),
		Exhausted:         burn >= 1,
	}
}
