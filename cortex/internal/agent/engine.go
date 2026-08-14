package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/governor"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/model"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/reasoning"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/slo"
)

type Engine struct {
	Reasoner reasoning.Reasoner
	Governor governor.Governor
}

func Default() Engine {
	return Engine{
		Reasoner: reasoning.HeuristicReasoner{},
		Governor: governor.Default(),
	}
}

func (e Engine) Analyze(snapshot model.SLOSnapshot, detections []model.Detection) model.Decision {
	budget := slo.Evaluate(snapshot)
	h := e.Reasoner.Investigate(detections)
	verdict, remediation, proof := e.Governor.Plan(snapshot.Service, detections, h, budget)

	return model.Decision{
		IncidentID:  incidentID(snapshot.Service, detections),
		Service:     snapshot.Service,
		Verdict:     verdict,
		Hypothesis:  h,
		Budget:      budget,
		Remediation: remediation,
		Proof:       proof,
	}
}

func incidentID(service string, detections []model.Detection) string {
	h := sha256.New()
	_, _ = fmt.Fprintln(h, service)
	for _, d := range detections {
		_, _ = fmt.Fprintf(h, "%s:%d:%d\n", d.RuleID, d.Event.CgroupID, d.Event.TGID)
	}
	return "ks-" + hex.EncodeToString(h.Sum(nil))[:12]
}
