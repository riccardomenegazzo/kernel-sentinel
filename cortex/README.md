# Sentinel Cortex

Sentinel Cortex is the reliability reasoning layer of Kernel Sentinel. It consumes newline-delimited JSON detections and turns them into an inspectable incident decision rather than directly mutating production.

## Requirements

- Go 1.22 or newer.
- No root privileges are required for replay/demo mode.
- The live Kernel Sentinel sensor is optional and Linux-only.

## Run the deterministic demo

From the repository root:

```bash
make demo
```

Or directly:

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

## Build a standalone binary

From the repository root:

```bash
make cortex-build
```

The resulting executable is `bin/cortex` (`bin/cortex.exe` when built manually on Windows).

You can also build directly:

```bash
cd cortex
go build -trimpath -o cortex ./cmd/cortex
```

## Input contract

`--detections` expects Kernel Sentinel detection objects, one JSON object per line. Unknown fields are tolerated so the Rust sensor and Cortex do not need lockstep releases.

The bundled `testdata/web-compromise.jsonl` fixture provides a reproducible incident containing two correlated detections in the same workload.

## Output contract

Cortex writes one JSON decision containing:

- `incident_id`
- `service`
- `verdict`
- `hypothesis`
- `budget`
- `remediation`
- `proof`

The remediation is proposal-only unless deterministic guardrails pass. Even then, the current repository deliberately does not register a live executor.

## Development

```bash
go test ./...
go vet ./...
```

The most important boundary is architectural: a future model-backed `Reasoner` may be probabilistic, but blast-radius policy, SLO gates and execution capabilities should remain deterministic and independently testable.
