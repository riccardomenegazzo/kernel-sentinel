# Sentinel Cortex: a proof-carrying reliability agent

Sentinel Cortex turns Kernel Sentinel from a runtime detector into a reliability reasoning layer. The key design choice is that the probabilistic part of the system may investigate and propose, but it never receives an unrestricted production mutation primitive.

```text
 eBPF / BPF LSM            Prometheus / OTel            deploy metadata
       |                         |                            |
       +------------ observations / evidence ----------------+
                                 |
                         incident correlation
                                 |
                     +-----------+-----------+
                     |                       |
                 investigator              skeptic
             proposes hypotheses      tries to falsify them
                     |                       |
                     +-----------+-----------+
                                 |
                         typed incident graph
                                 |
                          SLO/error-budget
                              governor
                                 |
                     proof-carrying remediation
                                 |
                  prepare -> execute -> verify -> rollback
```

## Why this is an agent, not a chat wrapper

The agent owns a closed operational loop: observe, correlate, hypothesize, challenge, plan, gate, verify and learn. Natural-language reasoning is replaceable behind the `Reasoner` interface. Safety, blast-radius limits and SLO policy are deterministic code.

## Proof-carrying remediation

A remediation proposal is incomplete unless it carries:

1. the concrete facts that support the hypothesis;
2. explicit alternative explanations and falsification checks;
3. preconditions that bound blast radius;
4. a reversible action;
5. postconditions that prove the action helped;
6. a rollback path when verification fails.

This is meant to prevent a common failure mode in autonomous operations: a plausible explanation becoming a production mutation without enough evidence.

## SLO-aware autonomy

Cortex computes how much of the service error budget has been consumed. High-confidence evidence is not sufficient by itself: the governor also considers whether users are currently being harmed. In the prototype, an exhausted budget plus confidence above the autonomous threshold yields `guardrails_passed`; execution still remains disabled until a real executor is deliberately registered.

## Demo

From the repository root:

```bash
cd cortex
go test ./...
go run ./cmd/cortex \
  --detections testdata/web-compromise.jsonl \
  --service workspace-runtime \
  --slo-target 0.999 \
  --good 99850 \
  --total 100000 \
  --window 30d
```

The output is a structured incident decision containing the hypothesis, confidence, error-budget state, remediation, verification plan and safety proof.

## Production path

The next layers should stay narrow and independently testable:

- OpenTelemetry/Prometheus adapters for metrics and traces;
- Kubernetes identity resolution from cgroup/container IDs to pod UID;
- a read-only investigation toolset first (logs, events, rollout history, traces);
- a capability-scoped Kubernetes executor with dry-run, PDB checks and namespace deny-lists;
- post-action verification using SLI queries, with automatic rollback;
- incident memory that stores evidence/action/outcome tuples, not raw chain-of-thought.

The design goal is not "an LLM with kubectl". It is an autonomous control loop whose risky decisions are inspectable, reversible and constrained by reliability policy.
