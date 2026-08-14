package agent

import (
	"testing"

	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/model"
)

func TestGuardrailsPassOnlyWithCorrelatedEvidenceAndBurn(t *testing.T) {
	containerID := "4b9d2f"
	exe := "/usr/bin/curl"
	parent := "sh"
	detections := []model.Detection{
		{
			RuleID: "KS-WEB-002", Severity: "critical", Score: 98,
			Event:   model.KernelEvent{Kind: "exec", TGID: 42, CgroupID: 91, Comm: "curl", Exe: &exe, ParentComm: &parent, Container: model.ContainerContext{Detected: true, ID: &containerID}},
			Lineage: []model.ProcessIdentity{{Comm: "nginx"}, {Comm: "sh"}},
		},
		{
			RuleID: "KS-WEB-003", Severity: "high", Score: 94,
			Event:   model.KernelEvent{Kind: "file_open", TGID: 42, CgroupID: 91, Comm: "curl", Exe: &exe, Container: model.ContainerContext{Detected: true, ID: &containerID}},
			Lineage: []model.ProcessIdentity{{Comm: "nginx"}},
		},
	}

	decision := Default().Analyze(model.SLOSnapshot{
		Service: "workspace-runtime", Target: 0.999, Good: 99850, Total: 100000,
	}, detections)

	if decision.Verdict != "guardrails_passed" {
		t.Fatalf("verdict=%q, want guardrails_passed", decision.Verdict)
	}
	if decision.Remediation.Mode != "safe_to_execute_if_executor_enabled" {
		t.Fatalf("mode=%q", decision.Remediation.Mode)
	}
	if !decision.Remediation.Reversible {
		t.Fatal("remediation must be reversible")
	}
}

func TestHealthySLOStillRequiresHumanApproval(t *testing.T) {
	containerID := "4b9d2f"
	exe := "/usr/bin/curl"
	ds := []model.Detection{
		{RuleID: "KS-WEB-002", Severity: "critical", Score: 98, Event: model.KernelEvent{Kind: "exec", TGID: 42, CgroupID: 91, Comm: "curl", Exe: &exe, Container: model.ContainerContext{Detected: true, ID: &containerID}}, Lineage: []model.ProcessIdentity{{Comm: "nginx"}}},
		{RuleID: "KS-WEB-003", Severity: "high", Score: 94, Event: model.KernelEvent{Kind: "file_open", TGID: 42, CgroupID: 91, Comm: "curl", Exe: &exe, Container: model.ContainerContext{Detected: true, ID: &containerID}}, Lineage: []model.ProcessIdentity{{Comm: "nginx"}}},
	}

	decision := Default().Analyze(model.SLOSnapshot{Service: "workspace-runtime", Target: 0.999, Good: 99990, Total: 100000}, ds)
	if decision.Verdict != "human_approval_required" {
		t.Fatalf("verdict=%q, want human_approval_required", decision.Verdict)
	}
}
