# kernel-sentinel

Linux runtime monitoring experiments with Rust, eBPF CO-RE and BPF LSM.

The current version collects process lifecycle and credential events in the kernel, sends them to a Rust userspace agent, enriches them with `/proc` and cgroup context, keeps a process ancestry table and evaluates a small YAML rule set.

This is intentionally a research prototype. I want the kernel side to stay small and predictable while most state, parsing and rule logic lives in Rust.

## Current event path

```text
sched tracepoints / file_open LSM
              |
           ringbuf
              |
              v
          Rust agent
              |
     +--------+--------+
     |                 |
 process graph     cgroup context
     |                 |
     +--------+--------+
              |
          YAML rules
              |
        JSON / terminal
```

Currently instrumented:

- successful process execution
- fork and exit
- `setuid(2)` attempts
- effective uid/gid from task credentials
- PID and mount namespace identifiers
- cgroup id
- file opens through a sleepable BPF LSM hook

The userspace side adds executable/cmdline information from `/proc`, basic Docker/containerd/Podman/Kubernetes cgroup recognition and parent-process context.

## Build

The project expects Linux with BTF exposed at `/sys/kernel/btf/vmlinux`. The LSM hooks also need BPF LSM enabled.

Typical Debian/Ubuntu dependencies:

```bash
sudo apt install clang llvm bpftool libelf-dev zlib1g-dev pkg-config
```

Generate the CO-RE header and build the BPF-enabled binary:

```bash
make bootstrap
cargo build --release --features bpf
```

or simply:

```bash
make release
```

`src/bpf/vmlinux.h` is generated from the running kernel and is not committed.

Run in the default audit-only mode:

```bash
sudo ./target/release/kernel-sentinel --policy policies/default.yaml
```

Print every normalized event as well as detections:

```bash
sudo ./target/release/kernel-sentinel --verbose-events
```

Terminal output is the default. For newline-delimited JSON suitable for `jq` or another collector:

```bash
sudo ./target/release/kernel-sentinel --output json
```

The Rust core can be tested without a BPF-capable kernel:

```bash
cargo test --lib
```

## Policy mode

The runtime stays audit-only unless an explicit cgroup is selected. The current prevention experiment rejects execution below `/tmp` only for that cgroup:

```bash
sudo ./target/release/kernel-sentinel --enforce-cgroup <CGROUP_ID>
```

The policy map is empty by default; there is no global deny mode. The narrow scope is deliberate because mistakes at an LSM decision point are much more expensive than mistakes in a userspace detection rule.

## Rules

Rules can match the current event, direct parent and bounded process ancestry. For example:

```yaml
- id: KS-WEB-002
  name: Downloader in web server process tree
  severity: critical
  score: 98
  match:
    event: exec
    ancestor_comm: nginx
    executable_suffix: /curl
```

This catches a downloader below an nginx process tree even when nginx is not the direct parent. The next meaningful step is bounded sequence state so related events can be evaluated as one chain rather than independent matches.

## Repository notes

- [`docs/architecture.md`](docs/architecture.md) describes the kernel/userspace split.
- [`docs/kernel-hooks.md`](docs/kernel-hooks.md) records why each observation point was chosen.
- [`docs/performance.md`](docs/performance.md) defines the benchmark methodology; no invented numbers are published.
- [`docs/roadmap.md`](docs/roadmap.md) tracks correctness and compatibility work.

## Known limitations

- container metadata is inferred from cgroup paths rather than OCI runtime state;
- the credential event records an attempted `setuid`, not a committed transition;
- PID reuse is not handled yet in the process table;
- there is no fallback backend for kernels without BPF LSM;
- ancestry-aware rules are still single-event matches rather than stateful event sequences;
- kernel integration tests still need a dedicated VM matrix.

## License

Apache-2.0 for userspace code. The BPF object declares a GPL-compatible license.
