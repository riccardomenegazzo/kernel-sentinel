package reasoning

import (
	"testing"

	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/model"
)

func TestCorrelatedWebDownloaderRaisesConfidence(t *testing.T) {
	id := "pod-abc"
	exe := "/usr/bin/curl"
	parent := "sh"
	ds := []model.Detection{
		{
			RuleID: "KS-WEB-002", Severity: "critical", Score: 98,
			Event:   model.KernelEvent{Kind: "exec", Comm: "curl", Exe: &exe, ParentComm: &parent, Container: model.ContainerContext{Detected: true, ID: &id}},
			Lineage: []model.ProcessIdentity{{Comm: "nginx", Exe: "/usr/sbin/nginx"}, {Comm: "sh", Exe: "/bin/sh"}},
		},
		{
			RuleID: "KS-WEB-003", Severity: "high", Score: 92,
			Event:   model.KernelEvent{Kind: "file_open", Comm: "curl", Exe: &exe, Container: model.ContainerContext{Detected: true, ID: &id}},
			Lineage: []model.ProcessIdentity{{Comm: "nginx", Exe: "/usr/sbin/nginx"}},
		},
	}

	h := (HeuristicReasoner{}).Investigate(ds)
	if h.Confidence < 0.92 {
		t.Fatalf("confidence=%f, want >= 0.92", h.Confidence)
	}
	if h.Cause == "runtime anomaly with unresolved root cause" {
		t.Fatalf("expected specific cause, got %q", h.Cause)
	}
}
