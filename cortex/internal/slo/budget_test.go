package slo

import (
	"math"
	"testing"

	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/model"
)

func TestEvaluateExhaustedBudget(t *testing.T) {
	b := Evaluate(model.SLOSnapshot{Target: 0.999, Good: 99850, Total: 100000})
	if !b.Exhausted {
		t.Fatalf("expected exhausted budget: %#v", b)
	}
	if math.Abs(b.BurnMultiple-1.5) > 0.0001 {
		t.Fatalf("burn multiple=%f, want 1.5", b.BurnMultiple)
	}
}

func TestEvaluateHealthyBudget(t *testing.T) {
	b := Evaluate(model.SLOSnapshot{Target: 0.999, Good: 99950, Total: 100000})
	if b.Exhausted {
		t.Fatalf("expected remaining budget: %#v", b)
	}
	if b.RemainingFraction <= 0 {
		t.Fatalf("remaining fraction=%f, want > 0", b.RemainingFraction)
	}
}
