package governor

import (
	"fmt"

	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/model"
)

type Governor struct {
	MinAutonomousConfidence float64
}

func Default() Governor {
	return Governor{MinAutonomousConfidence: 0.92}
}

func (g Governor) Plan(service string, detections []model.Detection, h model.Hypothesis, budget model.Budget) (string, model.Remediation, model.Proof) {
	target := workloadTarget(detections)
	proof := model.Proof{
		Facts: append([]string{}, h.Evidence...),
		RejectedShortcuts: []string{
			"do not restart a workload solely because an LLM suggested it",
			"do not mutate production from a single uncorrelated signal",
			"do not treat log similarity as proof of causality",
		},
		SafetyConstraints: []string{
			"target must resolve to exactly one workload",
			"at least two healthy replicas must remain available",
			"PodDisruptionBudget must permit the action",
			"control-plane and system namespaces are never autonomous targets",
			"every action must have an explicit rollback and postcondition check",
		},
	}

	remediation := model.Remediation{
		Action:     "quarantine-and-replace-workload",
		Target:     target,
		Mode:       "proposal_only",
		Risk:       "medium",
		Reversible: true,
		Preconditions: []string{
			"map kernel cgroup identity to one Kubernetes pod UID",
			"confirm a clean replica is available before isolation",
			"snapshot deployment and network-policy state",
		},
		Rollback: []string{
			"remove the temporary quarantine network policy",
			"restore the previous ReplicaSet if the replacement regresses",
		},
		Verification: []string{
			"no new matching kernel-sentinel detections for 5 minutes",
			"HTTP error-rate burn returns below 1x SLO budget rate",
			"p95 latency returns to the pre-incident envelope",
		},
	}

	if h.Confidence < 0.75 {
		remediation.Action = "collect-more-evidence"
		remediation.Risk = "none"
		remediation.Preconditions = h.Falsifiers
		remediation.Rollback = nil
		remediation.Verification = []string{"increase confidence with independent telemetry"}
		return "observe", remediation, proof
	}

	if h.Confidence < g.MinAutonomousConfidence {
		return "human_approval_required", remediation, proof
	}

	if !budget.Exhausted {
		return "human_approval_required", remediation, proof
	}

	remediation.Mode = "safe_to_execute_if_executor_enabled"
	return "guardrails_passed", remediation, proof
}

func workloadTarget(detections []model.Detection) string {
	for _, d := range detections {
		if d.Event.Container.ID != nil && *d.Event.Container.ID != "" {
			return "container:" + *d.Event.Container.ID
		}
		if d.Event.CgroupID != 0 {
			return fmt.Sprintf("cgroup:%d", d.Event.CgroupID)
		}
	}
	return "unresolved-workload"
}
