package model

import "time"

type ContainerContext struct {
	Detected bool    `json:"detected"`
	Runtime  *string `json:"runtime"`
	ID       *string `json:"id"`
}

type KernelEvent struct {
	ObservedAt time.Time        `json:"observed_at"`
	Kind       string           `json:"kind"`
	PID        uint32           `json:"pid"`
	TGID       uint32           `json:"tgid"`
	PPID       uint32           `json:"ppid"`
	CgroupID   uint64           `json:"cgroup_id"`
	Comm       string           `json:"comm"`
	Path       *string          `json:"path"`
	ParentComm *string          `json:"parent_comm"`
	ParentExe  *string          `json:"parent_exe"`
	Exe        *string          `json:"exe"`
	Cmdline    []string         `json:"cmdline"`
	Container  ContainerContext `json:"container"`
}

type ProcessIdentity struct {
	TGID uint32 `json:"tgid"`
	Comm string `json:"comm"`
	Exe  string `json:"exe"`
}

type Detection struct {
	DetectedAt  time.Time         `json:"detected_at"`
	RuleID      string            `json:"rule_id"`
	RuleName    string            `json:"rule_name"`
	Severity    string            `json:"severity"`
	Score       uint32            `json:"score"`
	Description string            `json:"description"`
	Tags        []string          `json:"tags"`
	Event       KernelEvent       `json:"event"`
	Lineage     []ProcessIdentity `json:"lineage"`
}

type SLOSnapshot struct {
	Service string  `json:"service"`
	Target  float64 `json:"target"`
	Good    uint64  `json:"good"`
	Total   uint64  `json:"total"`
	Window  string  `json:"window"`
}

type Budget struct {
	Target            float64 `json:"target"`
	Observed          float64 `json:"observed"`
	AllowedBadEvents  float64 `json:"allowed_bad_events"`
	ActualBadEvents   uint64  `json:"actual_bad_events"`
	BurnMultiple      float64 `json:"burn_multiple"`
	RemainingFraction float64 `json:"remaining_fraction"`
	Exhausted         bool    `json:"exhausted"`
}

type Hypothesis struct {
	Cause        string   `json:"cause"`
	Confidence   float64  `json:"confidence"`
	Evidence     []string `json:"evidence"`
	Falsifiers   []string `json:"falsifiers"`
	Alternatives []string `json:"alternatives"`
}

type Remediation struct {
	Action        string   `json:"action"`
	Target        string   `json:"target"`
	Mode          string   `json:"mode"`
	Risk          string   `json:"risk"`
	Reversible    bool     `json:"reversible"`
	Preconditions []string `json:"preconditions"`
	Rollback      []string `json:"rollback"`
	Verification  []string `json:"verification"`
}

type Proof struct {
	Facts             []string `json:"facts"`
	RejectedShortcuts []string `json:"rejected_shortcuts"`
	SafetyConstraints []string `json:"safety_constraints"`
}

type Decision struct {
	IncidentID  string      `json:"incident_id"`
	Service     string      `json:"service"`
	Verdict     string      `json:"verdict"`
	Hypothesis  Hypothesis  `json:"hypothesis"`
	Budget      Budget      `json:"budget"`
	Remediation Remediation `json:"remediation"`
	Proof       Proof       `json:"proof"`
}
