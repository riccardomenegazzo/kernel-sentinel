# kernel-sentinel

Kernel Sentinel is a Linux runtime sensor written in Rust/eBPF plus **Sentinel Cortex**, an SRE-oriented reliability agent that correlates runtime evidence, evaluates SLO/error-budget state and produces proof-carrying remediation plans.

The project is designed so that the probabilistic reasoning layer can investigate and propose while deterministic policy controls whether a production action is even eligible to run.

## 60-second demo

You can test Cortex without root, eBPF or Kubernetes. You only need Go 1.22+:

```bash
git clone https://github.com/riccardomenegazzo/kernel-sentinel.git
cd kernel-sentinel
make demo
```

The demo replays a deterministic incident where a downloader appears inside an nginx process tree and is followed by sensitive credential access. Cortex correlates the evidence, challenges the hypothesis, computes the SLO burn and emits a reversible remediation plan.

If you do not have `make`, run:

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

See [`docs/quickstart.md`](docs/quickstart.md) for platform-specific setup and the live Linux sensor workflow.

## Architecture

```text
Linux kernel                         Reliability control plane

tracepoints / BPF LSM
        |
     ringbuf
        |
        v
  Rust sensor ---- JSONL evidence ----> Sentinel Cortex
                                      /      |       \
                              investigator  SLO    governor
                                   |         |        |
                                   +---------+--------+
                                             |
                                  proof-carrying remediation
                                             |
                               prepare -> verify -> rollback
```

The current sensor collects process lifecycle, credential and file-open events, enriches them with `/proc`, cgroup/container context and process ancestry, and evaluates YAML policies.

Cortex consumes detections and produces a structured incident decision containing:

- a root-cause hypothesis with confidence;
- supporting evidence and explicit falsifiers;
- alternative explanations;
- SLO/error-budget state;
- a scoped remediation proposal;
- preconditions, verification steps and rollback;
- safety constraints and shortcuts the agent deliberately refused to take.

## Build Cortex

```bash
make cortex-build
./bin/cortex \
  --detections cortex/testdata/web-compromise.jsonl \
  --service workspace-runtime \
  --slo-target 0.999 \
  --good 99850 \
  --total 100000
```

Tagged releases automatically build Cortex binaries for Linux, macOS and Windows on amd64/arm64 where supported.

## Build the live eBPF sensor

The kernel sensor requires Linux with BTF exposed at `/sys/kernel/btf/vmlinux`. BPF LSM hooks also require BPF LSM support.

Typical Debian/Ubuntu dependencies:

```bash
sudo apt install clang llvm bpftool libelf-dev zlib1g-dev pkg-config
```

Install a Rust toolchain, then:

```bash
make doctor
make release
sudo ./target/release/kernel-sentinel --policy policies/default.yaml
```

For newline-delimited JSON suitable for Cortex or another collector:

```bash
sudo ./target/release/kernel-sentinel --output json
```

`src/bpf/vmlinux.h` is generated from the running kernel and is intentionally not committed.

## Policy mode

The runtime stays audit-only unless an explicit cgroup is selected. The prevention experiment rejects execution below `/tmp` only for that cgroup:

```bash
sudo ./target/release/kernel-sentinel --enforce-cgroup <CGROUP_ID>
```

The policy map is empty by default; there is no global deny mode. The narrow scope is deliberate because mistakes at an LSM decision point are much more expensive than mistakes in a userspace detection rule.

## Project layout

```text
src/                    Rust userspace sensor
src/bpf/                eBPF/BPF LSM programs
policies/               YAML runtime detection policies
cortex/                 reliability reasoning agent
cortex/testdata/        deterministic replay incidents
docs/                   architecture, quickstart and design notes
scripts/                bootstrap, demo and environment checks
.github/workflows/      CI and release automation
```

## Validation

CI checks:

- Rust formatting, unit tests and Clippy;
- native eBPF-enabled compilation on Linux;
- Cortex Go tests.

Locally:

```bash
make test
```

The live eBPF build is Linux-only, but the Cortex demo and tests run anywhere Go runs.

## Design notes

- [`docs/quickstart.md`](docs/quickstart.md) — clone, build and test paths.
- [`docs/cortex.md`](docs/cortex.md) — proof-carrying reliability-agent architecture.
- [`docs/interview-demo.md`](docs/interview-demo.md) — five-minute walkthrough.
- [`docs/architecture.md`](docs/architecture.md) — kernel/userspace split.
- [`docs/kernel-hooks.md`](docs/kernel-hooks.md) — hook selection and trade-offs.
- [`docs/performance.md`](docs/performance.md) — benchmark methodology.
- [`docs/threat-model.md`](docs/threat-model.md) — security assumptions.
- [`docs/roadmap.md`](docs/roadmap.md) — correctness and compatibility work.

## Known limitations

- Cortex currently reasons over supplied evidence rather than querying Prometheus/OpenTelemetry/Kubernetes directly;
- no live production executor is registered by default;
- container metadata is inferred from cgroup paths rather than OCI runtime state;
- the credential event records an attempted `setuid`, not a committed transition;
- PID reuse is not handled yet in the process table;
- there is no fallback sensor backend for kernels without BPF LSM;
- kernel integration tests still need a dedicated VM matrix.

## License

Apache-2.0 for userspace code. The BPF object declares a GPL-compatible license.
