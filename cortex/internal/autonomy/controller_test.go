package autonomy

import (
	"context"
	"testing"
	"time"

	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/kubernetes"
)

type seqMetrics struct {
	vals []float64
	i    int
}

func (s *seqMetrics) Query(context.Context, string, time.Time) (float64, error) {
	v := s.vals[s.i]
	if s.i < len(s.vals)-1 {
		s.i++
	}
	return v, nil
}

type fakeCluster struct {
	plan            kubernetes.RollbackPlan
	dry, exec, comp int
}

func (f *fakeCluster) PlanRollback(context.Context, string, string) (kubernetes.RollbackPlan, error) {
	return f.plan, nil
}
func (f *fakeCluster) PatchImages(_ context.Context, _ kubernetes.RollbackPlan, _ map[string]string, dry bool) error {
	if dry {
		f.dry++
	} else {
		f.exec++
	}
	return nil
}
func (f *fakeCluster) PatchCurrentImages(_ context.Context, _ string, _ string, _ map[string]string, dry bool) error {
	if !dry {
		f.comp++
	}
	return nil
}
func (f *fakeCluster) WaitReady(context.Context, string, string, time.Duration) error { return nil }

type memAudit struct{ actions []string }

func (a *memAudit) Append(_ string, action string, _ any) error {
	a.actions = append(a.actions, action)
	return nil
}
func baseConfig() Config {
	return Config{Service: "checkout", Namespace: "prod", Deployment: "checkout", SLOTarget: .999, ErrorRateQuery: "errors", MinConfidence: .85, MinReadyReplicas: 2, RequiredBadCycles: 1, MaxRevisionAge: time.Hour, Cooldown: time.Nanosecond}
}
func plan() kubernetes.RollbackPlan {
	return kubernetes.RollbackPlan{Namespace: "prod", Deployment: "checkout", ResourceVersion: "1", CurrentRevision: 8, PreviousRevision: 7, CurrentImages: map[string]string{"app": "app:v8"}, PreviousImages: map[string]string{"app": "app:v7"}, DesiredReplicas: 3, ReadyReplicas: 3, CurrentRevisionCreatedAt: time.Unix(0, 0)}
}

func TestControllerProposalDryRunsButDoesNotExecute(t *testing.T) {
	m := &seqMetrics{vals: []float64{.01}}
	cl := &fakeCluster{plan: plan()}
	a := &memAudit{}
	c := Controller{Config: baseConfig(), Metrics: m, Cluster: cl, Audit: a, Now: func() time.Time { return time.Unix(1, 0) }}
	r, err := c.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != "guardrails_passed" || cl.dry != 1 || cl.exec != 0 {
		t.Fatalf("result=%+v dry=%d exec=%d", r, cl.dry, cl.exec)
	}
}

func TestControllerExecutesAndVerifies(t *testing.T) {
	cfg := baseConfig()
	cfg.Execute = true
	m := &seqMetrics{vals: []float64{.01, .0005}}
	cl := &fakeCluster{plan: plan()}
	c := Controller{Config: cfg, Metrics: m, Cluster: cl, Audit: &memAudit{}, Now: func() time.Time { return time.Unix(1, 0) }}
	r, err := c.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != "remediated" || !r.Executed || cl.exec != 1 || cl.comp != 0 {
		t.Fatalf("result=%+v exec=%d comp=%d", r, cl.exec, cl.comp)
	}
}

func TestControllerCompensatesFailedPostcondition(t *testing.T) {
	cfg := baseConfig()
	cfg.Execute = true
	m := &seqMetrics{vals: []float64{.01, .02}}
	cl := &fakeCluster{plan: plan()}
	c := Controller{Config: cfg, Metrics: m, Cluster: cl, Audit: &memAudit{}, Now: func() time.Time { return time.Unix(1, 0) }}
	r, err := c.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != "compensated" || !r.RolledBackCompensation || cl.comp != 1 {
		t.Fatalf("result=%+v comp=%d", r, cl.comp)
	}
}

func TestProtectedNamespaceNeverMutates(t *testing.T) {
	cfg := baseConfig()
	cfg.Namespace = "kube-system"
	m := &seqMetrics{vals: []float64{.01}}
	cl := &fakeCluster{plan: plan()}
	c := Controller{Config: cfg, Metrics: m, Cluster: cl}
	r, err := c.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != "blocked" || cl.dry+cl.exec+cl.comp != 0 {
		t.Fatalf("result=%+v", r)
	}
}
