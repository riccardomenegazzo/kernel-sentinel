# Five-minute interview demo: Sentinel Cortex

## 1. Start with the problem

"Most coding agents optimize for producing changes. An SRE agent has a different failure model: a confident but wrong action can amplify an incident. I built the control plane around evidence and reversibility rather than around prompt fluency."

## 2. Show the sensor

Kernel Sentinel collects process and file activity with eBPF/BPF LSM and enriches it in Rust. The demo incident contains a downloader inside an nginx process tree followed by sensitive file access in the same workload.

## 3. Run Cortex

```bash
cd cortex
go test ./...
go run ./cmd/cortex \
  --detections testdata/web-compromise.jsonl \
  --service workspace-runtime \
  --slo-target 0.999 \
  --good 99850 \
  --total 100000
```

Point out four fields in the JSON output:

- `hypothesis`: the likely root cause plus confidence and alternative explanations;
- `budget`: whether user-visible reliability is burning through the SLO;
- `remediation`: a scoped, reversible action with preconditions and verification;
- `proof`: shortcuts the agent refused to take and safety constraints that must hold.

## 4. Explain the design boundary

"I intentionally did not give the prototype an unrestricted executor. The model-facing reasoning layer can be swapped for a stronger model, but the governor stays deterministic. Production actions require target uniqueness, replica safety, PDB checks, namespace restrictions, rollback state and postcondition verification."

## 5. Close with the roadmap

The next milestone is a Kubernetes read-only investigator plus Prometheus/OpenTelemetry adapters. After that, add one narrowly scoped remediation capability and prove it in a fault-injection environment before allowing any autonomous production mutation.
