package autonomy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/evidence"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/kubernetes"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/loki"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/model"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/slo"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/tempo"
)

type Config struct {
	Service             string        `json:"service"`
	Namespace           string        `json:"namespace"`
	Deployment          string        `json:"deployment"`
	SLOTarget           float64       `json:"slo_target"`
	ErrorRateQuery      string        `json:"error_rate_query"`
	P95Query            string        `json:"p95_query,omitempty"`
	TraceQuery          string        `json:"trace_query,omitempty"`
	LogQuery            string        `json:"log_query,omitempty"`
	MinConfidence       float64       `json:"min_confidence"`
	MinReadyReplicas    int32         `json:"min_ready_replicas"`
	ProtectedNamespaces []string      `json:"protected_namespaces,omitempty"`
	Execute             bool          `json:"execute"`
	RequiredBadCycles   int           `json:"required_bad_cycles,omitempty"`
	RolloutTimeout      time.Duration `json:"-"`
	VerifyDelay         time.Duration `json:"-"`
	MaxRevisionAge      time.Duration `json:"-"`
	Cooldown            time.Duration `json:"-"`
}

func (c *Config) Defaults() {
	if c.SLOTarget == 0 {
		c.SLOTarget = .999
	}
	if c.MinConfidence == 0 {
		c.MinConfidence = .90
	}
	if c.MinReadyReplicas == 0 {
		c.MinReadyReplicas = 2
	}
	if c.RolloutTimeout == 0 {
		c.RolloutTimeout = 2 * time.Minute
	}
	if c.RequiredBadCycles == 0 {
		c.RequiredBadCycles = 2
	}
	if c.MaxRevisionAge == 0 {
		c.MaxRevisionAge = 30 * time.Minute
	}
	if c.Cooldown == 0 {
		c.Cooldown = 10 * time.Minute
	}
	if c.ProtectedNamespaces == nil {
		c.ProtectedNamespaces = []string{"kube-system", "kube-public", "kube-node-lease"}
	}
}

func (c Config) Validate() error {
	if c.Service == "" || c.Namespace == "" || c.Deployment == "" {
		return fmt.Errorf("service, namespace and deployment are required")
	}
	if c.ErrorRateQuery == "" {
		return fmt.Errorf("error_rate_query is required")
	}
	if c.SLOTarget <= 0 || c.SLOTarget >= 1 {
		return fmt.Errorf("slo_target must be between 0 and 1")
	}
	return nil
}

type Metrics interface {
	Query(context.Context, string, time.Time) (float64, error)
}
type Logs interface {
	QueryRange(context.Context, string, time.Time, time.Time, int) ([]loki.Entry, error)
}
type Traces interface {
	Search(context.Context, string, time.Time, time.Time, int) ([]tempo.Trace, error)
}
type Cluster interface {
	PlanRollback(context.Context, string, string) (kubernetes.RollbackPlan, error)
	PatchImages(context.Context, kubernetes.RollbackPlan, map[string]string, bool) error
	PatchCurrentImages(context.Context, string, string, map[string]string, bool) error
	WaitReady(context.Context, string, string, time.Duration) error
}
type Auditor interface {
	Append(string, string, any) error
}

type Controller struct {
	Config       Config
	Metrics      Metrics
	Traces       Traces
	Logs         Logs
	Cluster      Cluster
	Audit        Auditor
	Now          func() time.Time
	mu           sync.Mutex
	badStreak    int
	lastRevision int
	lastAction   time.Time
}

type Result struct {
	IncidentID             string                   `json:"incident_id"`
	Service                string                   `json:"service"`
	Verdict                string                   `json:"verdict"`
	Cause                  string                   `json:"cause"`
	Confidence             float64                  `json:"confidence"`
	Budget                 model.Budget             `json:"budget"`
	Plan                   *kubernetes.RollbackPlan `json:"rollback_plan,omitempty"`
	Evidence               evidence.Snapshot        `json:"evidence"`
	ErrorRateBefore        float64                  `json:"error_rate_before"`
	ErrorRateAfter         *float64                 `json:"error_rate_after,omitempty"`
	P95Before              *float64                 `json:"p95_before,omitempty"`
	P95After               *float64                 `json:"p95_after,omitempty"`
	Executed               bool                     `json:"executed"`
	RolledBackCompensation bool                     `json:"rolled_back_compensation"`
	Reason                 string                   `json:"reason"`
}

func (c *Controller) RunOnce(ctx context.Context) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg := c.Config
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	if c.Metrics == nil || c.Cluster == nil {
		return Result{}, fmt.Errorf("metrics and cluster providers are required")
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	incident := incidentID(cfg, now)
	g := evidence.New()
	if protected(cfg.Namespace, cfg.ProtectedNamespaces) {
		r := Result{IncidentID: incident, Service: cfg.Service, Verdict: "blocked", Reason: "namespace is protected"}
		audit(c.Audit, incident, "blocked", r)
		return r, nil
	}

	plan, err := c.Cluster.PlanRollback(ctx, cfg.Namespace, cfg.Deployment)
	if err != nil {
		if errors.Is(err, kubernetes.ErrNoPreviousRevision) {
			r := Result{IncidentID: incident, Service: cfg.Service, Verdict: "observe", Reason: "no previous deployment revision is available for safe rollback"}
			audit(c.Audit, incident, "observe", r)
			return r, nil
		}
		return Result{}, fmt.Errorf("plan rollback: %w", err)
	}
	g.Add(evidence.Node{ID: "deployment", Kind: evidence.KindDeployment, ObservedAt: now, Source: "kubernetes", Summary: fmt.Sprintf("deployment %s/%s revision %d, previous %d", plan.Namespace, plan.Deployment, plan.CurrentRevision, plan.PreviousRevision), Attributes: map[string]string{"ready": fmt.Sprint(plan.ReadyReplicas), "desired": fmt.Sprint(plan.DesiredReplicas)}})
	if plan.CurrentRevisionCreatedAt.IsZero() || now.Sub(plan.CurrentRevisionCreatedAt) < 0 || now.Sub(plan.CurrentRevisionCreatedAt) > cfg.MaxRevisionAge {
		r := Result{IncidentID: incident, Service: cfg.Service, Verdict: "observe", Plan: &plan, Evidence: g.Snapshot(), Reason: "current ReplicaSet is not recent enough to establish deploy correlation"}
		audit(c.Audit, incident, "observe", r)
		return r, nil
	}
	if !c.lastAction.IsZero() && now.Sub(c.lastAction) < cfg.Cooldown {
		r := Result{IncidentID: incident, Service: cfg.Service, Verdict: "cooldown", Plan: &plan, Evidence: g.Snapshot(), Reason: "autonomous mutation cooldown active"}
		audit(c.Audit, incident, "cooldown", r)
		return r, nil
	}

	errRate, err := c.Metrics.Query(ctx, cfg.ErrorRateQuery, now)
	if err != nil {
		return Result{}, fmt.Errorf("query error rate: %w", err)
	}
	budget := slo.EvaluateErrorRate(cfg.SLOTarget, errRate)
	if budget.Exhausted {
		if c.lastRevision == plan.CurrentRevision {
			c.badStreak++
		} else {
			c.lastRevision = plan.CurrentRevision
			c.badStreak = 1
		}
	} else {
		c.badStreak = 0
		c.lastRevision = plan.CurrentRevision
	}
	g.Add(evidence.Node{ID: "metric:error-rate", Kind: evidence.KindMetric, ObservedAt: now, Source: "prometheus", Summary: fmt.Sprintf("error rate %.6f, burn %.2fx", errRate, budget.BurnMultiple), Attributes: map[string]string{"query": cfg.ErrorRateQuery}, Confidence: .99})
	_ = g.Link(evidence.Edge{From: "deployment", To: "metric:error-rate", Relation: "coincident_with", Weight: .6})

	var p95 *float64
	if cfg.P95Query != "" {
		v, e := c.Metrics.Query(ctx, cfg.P95Query, now)
		if e == nil {
			p95 = &v
			g.Add(evidence.Node{ID: "metric:p95", Kind: evidence.KindMetric, ObservedAt: now, Source: "prometheus", Summary: fmt.Sprintf("p95 %.6f", v), Attributes: map[string]string{"query": cfg.P95Query}, Confidence: .99})
			_ = g.Link(evidence.Edge{From: "deployment", To: "metric:p95", Relation: "coincident_with", Weight: .5})
		}
	}

	logCount := 0
	if c.Logs != nil && cfg.LogQuery != "" {
		entries, e := c.Logs.QueryRange(ctx, cfg.LogQuery, now.Add(-10*time.Minute), now, 50)
		if e == nil {
			logCount = len(entries)
			for i, entry := range entries {
				if i >= 5 {
					break
				}
				id := fmt.Sprintf("log:%d", i)
				g.Add(evidence.Node{ID: id, Kind: evidence.KindRuntime, ObservedAt: now, Source: "loki", Summary: entry.Line, Attributes: entry.Labels, Confidence: .8})
				_ = g.Link(evidence.Edge{From: "deployment", To: id, Relation: "observed_after_revision", Weight: .5})
			}
		}
	}

	traceCount := 0
	if c.Traces != nil && cfg.TraceQuery != "" {
		traces, e := c.Traces.Search(ctx, cfg.TraceQuery, now.Add(-10*time.Minute), now, 20)
		if e == nil {
			traceCount = len(traces)
			for i, t := range traces {
				if i >= 5 {
					break
				}
				id := "trace:" + t.TraceID
				g.Add(evidence.Node{ID: id, Kind: evidence.KindTrace, ObservedAt: now, Source: "tempo", Summary: fmt.Sprintf("%s %s %.1fms", t.RootServiceName, t.RootTraceName, t.DurationMs), Attributes: map[string]string{"trace_id": t.TraceID}, Confidence: .95})
				_ = g.Link(evidence.Edge{From: "deployment", To: id, Relation: "observed_after_revision", Weight: .7})
			}
		}
	}

	confidence := .55
	if budget.Exhausted {
		confidence += .20
	}
	if plan.PreviousRevision > 0 {
		confidence += .10
	}
	if traceCount > 0 {
		confidence += .10
	}
	if logCount > 0 {
		confidence += .05
	}
	if p95 != nil {
		confidence += .03
	}
	if plan.ReadyReplicas >= plan.DesiredReplicas && plan.DesiredReplicas > 0 {
		confidence += .02
	}
	confidence = math.Min(.99, confidence)
	cause := fmt.Sprintf("probable deployment regression at revision %d", plan.CurrentRevision)
	res := Result{IncidentID: incident, Service: cfg.Service, Verdict: "observe", Cause: cause, Confidence: confidence, Budget: budget, Plan: &plan, Evidence: g.Snapshot(), ErrorRateBefore: errRate, P95Before: p95, Reason: "insufficient evidence or error-budget impact"}

	if !budget.Exhausted {
		audit(c.Audit, incident, "observe", res)
		return res, nil
	}
	if c.badStreak < cfg.RequiredBadCycles {
		res.Verdict = "observe"
		res.Reason = fmt.Sprintf("waiting for persistent signal: bad cycle %d/%d", c.badStreak, cfg.RequiredBadCycles)
		audit(c.Audit, incident, "observe", res)
		return res, nil
	}
	if confidence < cfg.MinConfidence {
		res.Verdict = "human_approval_required"
		res.Reason = "confidence below autonomous threshold"
		audit(c.Audit, incident, "approval_required", res)
		return res, nil
	}
	if plan.DesiredReplicas < cfg.MinReadyReplicas || plan.ReadyReplicas < cfg.MinReadyReplicas {
		res.Verdict = "blocked"
		res.Reason = "replica safety guard failed"
		audit(c.Audit, incident, "blocked", res)
		return res, nil
	}
	if len(plan.PreviousImages) == 0 || !sameKeys(plan.CurrentImages, plan.PreviousImages) || equalImages(plan.CurrentImages, plan.PreviousImages) {
		res.Verdict = "blocked"
		res.Reason = "previous revision must contain the same container set with distinct images"
		audit(c.Audit, incident, "blocked", res)
		return res, nil
	}
	if err := c.Cluster.PatchImages(ctx, plan, plan.PreviousImages, true); err != nil {
		res.Verdict = "blocked"
		res.Reason = "Kubernetes server-side dry-run rejected rollback: " + err.Error()
		audit(c.Audit, incident, "dry_run_rejected", res)
		return res, nil
	}
	res.Verdict = "guardrails_passed"
	res.Reason = "rollback dry-run accepted; execution disabled"
	audit(c.Audit, incident, "guardrails_passed", res)
	if !cfg.Execute {
		return res, nil
	}

	audit(c.Audit, incident, "execute_rollback", plan)
	c.lastAction = now
	if err := c.Cluster.PatchImages(ctx, plan, plan.PreviousImages, false); err != nil {
		return res, fmt.Errorf("execute rollback: %w", err)
	}
	res.Executed = true
	res.Verdict = "verifying"
	res.Reason = "rollback applied; verifying rollout and SLI"
	rollCtx, cancel := context.WithTimeout(ctx, cfg.RolloutTimeout)
	defer cancel()
	if err := c.Cluster.WaitReady(rollCtx, cfg.Namespace, cfg.Deployment, 2*time.Second); err != nil {
		return c.compensate(ctx, cfg, res, plan, "rollout failed: "+err.Error())
	}
	if cfg.VerifyDelay > 0 {
		t := time.NewTimer(cfg.VerifyDelay)
		select {
		case <-ctx.Done():
			t.Stop()
			return res, ctx.Err()
		case <-t.C:
		}
	}
	after, err := c.Metrics.Query(ctx, cfg.ErrorRateQuery, time.Now().UTC())
	if err != nil {
		return c.compensate(ctx, cfg, res, plan, "post-rollback error-rate query failed: "+err.Error())
	}
	res.ErrorRateAfter = &after
	var p95After *float64
	if cfg.P95Query != "" {
		if v, e := c.Metrics.Query(ctx, cfg.P95Query, time.Now().UTC()); e == nil {
			p95After = &v
			res.P95After = &v
		}
	}
	allowed := 1 - cfg.SLOTarget
	latencyOK := p95 == nil || p95After == nil || *p95After <= *p95*1.20
	if after > allowed || !latencyOK {
		return c.compensate(ctx, cfg, res, plan, fmt.Sprintf("postcondition failed: error_rate=%.6f allowed=%.6f latency_ok=%t", after, allowed, latencyOK))
	}
	res.Verdict = "remediated"
	res.Reason = "rollback verified: rollout healthy and SLI within postconditions"
	audit(c.Audit, incident, "verified", res)
	return res, nil
}

func (c *Controller) compensate(ctx context.Context, cfg Config, res Result, plan kubernetes.RollbackPlan, reason string) (Result, error) {
	audit(c.Audit, res.IncidentID, "verification_failed", map[string]any{"reason": reason})
	if err := c.Cluster.PatchCurrentImages(ctx, cfg.Namespace, cfg.Deployment, plan.CurrentImages, true); err != nil {
		return res, fmt.Errorf("%s; compensation dry-run failed: %w", reason, err)
	}
	if err := c.Cluster.PatchCurrentImages(ctx, cfg.Namespace, cfg.Deployment, plan.CurrentImages, false); err != nil {
		return res, fmt.Errorf("%s; compensation failed: %w", reason, err)
	}
	res.RolledBackCompensation = true
	res.Verdict = "compensated"
	res.Reason = reason + "; restored original images"
	audit(c.Audit, res.IncidentID, "compensated", res)
	return res, nil
}

func protected(ns string, list []string) bool {
	for _, v := range list {
		if ns == v {
			return true
		}
	}
	return false
}
func sameKeys(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func equalImages(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func incidentID(c Config, t time.Time) string {
	h := sha256.Sum256([]byte(strings.Join([]string{c.Service, c.Namespace, c.Deployment, t.Format("2006-01-02T15:04")}, "|")))
	return "sre-" + hex.EncodeToString(h[:])[:12]
}
func audit(a Auditor, id, action string, p any) {
	if a != nil {
		_ = a.Append(id, action, p)
	}
}
