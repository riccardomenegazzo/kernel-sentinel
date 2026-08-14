# Quickstart

This repository has two independently testable layers:

1. **Sentinel Cortex** — the reliability agent. It runs on Linux, macOS or Windows anywhere Go runs.
2. **Kernel Sentinel** — the live Rust/eBPF runtime sensor. It requires Linux.

If you only want to evaluate the agent, start with Cortex. You do not need root, Kubernetes or eBPF.

## Option A: 60-second Cortex replay

Requirements: Git and Go 1.22+.

```bash
git clone https://github.com/riccardomenegazzo/kernel-sentinel.git
cd kernel-sentinel
make demo
```

Without `make`:

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

Expected behavior: the agent correlates two runtime detections, produces a high-confidence compromise hypothesis, observes that the supplied SLO window has exceeded its error budget and returns a reversible quarantine/replace remediation plan guarded by explicit safety constraints.

## Option B: build Cortex once

Unix-like systems:

```bash
make cortex-build
./bin/cortex \
  --detections cortex/testdata/web-compromise.jsonl \
  --service workspace-runtime \
  --slo-target 0.999 \
  --good 99850 \
  --total 100000
```

Windows PowerShell:

```powershell
cd cortex
go test ./...
go build -trimpath -o cortex.exe ./cmd/cortex
.\cortex.exe --detections testdata\web-compromise.jsonl --service workspace-runtime --slo-target 0.999 --good 99850 --total 100000
```

## Option C: run the live Linux sensor

Requirements:

- Linux with `/sys/kernel/btf/vmlinux` readable;
- Rust stable toolchain;
- clang/LLVM;
- bpftool;
- libelf, zlib and pkg-config development packages;
- BPF LSM support for the LSM hooks.

Debian/Ubuntu example:

```bash
sudo apt update
sudo apt install -y clang llvm bpftool libelf-dev zlib1g-dev pkg-config
```

Check the environment:

```bash
make doctor
```

Build:

```bash
make release
```

Run audit-only:

```bash
sudo ./target/release/kernel-sentinel --policy policies/default.yaml
```

Run JSON output suitable for collection:

```bash
sudo ./target/release/kernel-sentinel --policy policies/default.yaml --output json
```

The sensor is intentionally not packaged in a generic cross-platform binary because its runtime semantics depend on Linux kernel capabilities. Cortex is separately distributable and can replay saved detection streams on any supported Go platform.

## Feeding captured detections to Cortex

Capture a bounded sensor window on Linux:

```bash
sudo timeout 60s ./target/release/kernel-sentinel \
  --policy policies/default.yaml \
  --output json > /tmp/kernel-sentinel-detections.jsonl || true
```

Then analyze it:

```bash
make cortex-build
./bin/cortex \
  --detections /tmp/kernel-sentinel-detections.jsonl \
  --service my-service \
  --slo-target 0.999 \
  --good 99900 \
  --total 100000
```

If the capture contains no detections, Cortex exits with `no detections supplied`; use the bundled replay fixture to validate the agent path independently of the sensor.

## CI and release artifacts

Every pull request tests Rust, eBPF compilation and Cortex. Tags matching `v*` trigger a release workflow that cross-compiles Cortex binaries and publishes them to a GitHub Release.
