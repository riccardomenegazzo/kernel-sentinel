package slo

import (
	"math"

	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/model"
)

func Evaluate(s model.SLOSnapshot) model.Budget {
	if s.Total == 0 {
		return model.Budget{Target: s.Target}
	}

	bad := s.Total - min(s.Good, s.Total)
	observed := float64(s.Good) / float64(s.Total)
	allowedBad := round6((1 - s.Target) * float64(s.Total))

	burn := 0.0
	remaining := 1.0
	if allowedBad > 0 {
		burn = round6(float64(bad) / allowedBad)
		remaining = round6(math.Max(0, (allowedBad-float64(bad))/allowedBad))
	}

	return model.Budget{
		Target:            s.Target,
		Observed:          observed,
		AllowedBadEvents:  allowedBad,
		ActualBadEvents:   bad,
		BurnMultiple:      burn,
		RemainingFraction: remaining,
		Exhausted:         burn >= 1,
	}
}

func round6(v float64) float64 {
	return math.Round(v*1_000_000) / 1_000_000
}
