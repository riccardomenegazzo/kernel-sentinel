package reasoning

import (
	"fmt"
	"math"
	"strings"

	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/model"
)

// Reasoner is intentionally an interface. A model-backed investigator can be
// plugged in later, while the safety governor remains deterministic.
type Reasoner interface {
	Investigate([]model.Detection) model.Hypothesis
}

type HeuristicReasoner struct{}

func (HeuristicReasoner) Investigate(detections []model.Detection) model.Hypothesis {
	if len(detections) == 0 {
		return model.Hypothesis{
			Cause:      "insufficient evidence",
			Confidence: 0,
			Falsifiers: []string{"collect runtime, metric, log and trace evidence"},
		}
	}

	confidence := 0.0
	webTree := false
	downloader := false
	container := false
	var evidence []string

	for _, d := range detections {
		confidence = math.Max(confidence, float64(d.Score)/100)
		if d.Event.Container.Detected {
			container = true
		}
		if isDownloader(d.Event) {
			downloader = true
		}
		if hasWebAncestor(d) {
			webTree = true
		}
		evidence = append(evidence, fmt.Sprintf("%s (%s) score=%d process=%s", d.RuleID, d.Severity, d.Score, d.Event.Comm))
	}

	cause := "runtime anomaly with unresolved root cause"
	alternatives := []string{"operator debugging activity", "legitimate health or bootstrap script"}
	falsifiers := []string{
		"prove the executable hash is expected for this deployment",
		"show the process lineage originated from an approved maintenance session",
	}

	if webTree && downloader {
		cause = "probable workload compromise: downloader executed inside a web-server process tree"
		confidence += 0.08
		alternatives = []string{"intentional application subprocess", "diagnostic command executed by an operator"}
		falsifiers = append(falsifiers,
			"show an application code path that intentionally spawns this downloader",
			"show matching authenticated operator activity in the same time window",
		)
	}
	if container {
		confidence += 0.03
	}
	if len(detections) > 1 {
		confidence += 0.04
		evidence = append(evidence, "multiple correlated detections reduce single-signal ambiguity")
	} else {
		confidence -= 0.08
		evidence = append(evidence, "skeptic penalty applied because only one detection is present")
	}
	confidence = math.Max(0, math.Min(0.99, confidence))

	return model.Hypothesis{
		Cause:        cause,
		Confidence:   confidence,
		Evidence:     evidence,
		Falsifiers:   falsifiers,
		Alternatives: alternatives,
	}
}

func isDownloader(e model.KernelEvent) bool {
	for _, value := range []string{e.Comm, deref(e.Exe), deref(e.Path)} {
		v := strings.ToLower(value)
		if strings.HasSuffix(v, "/curl") || strings.HasSuffix(v, "/wget") || v == "curl" || v == "wget" {
			return true
		}
	}
	return false
}

func hasWebAncestor(d model.Detection) bool {
	for _, p := range d.Lineage {
		if webProcess(p.Comm) {
			return true
		}
	}
	return d.Event.ParentComm != nil && webProcess(*d.Event.ParentComm)
}

func webProcess(comm string) bool {
	switch strings.ToLower(comm) {
	case "nginx", "apache2", "httpd", "caddy", "node", "gunicorn", "uvicorn":
		return true
	default:
		return false
	}
}

func deref(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
