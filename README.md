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

The project expects Linux with BTF exposed at `/sys/kernel/btf/vmlinux`. The file-open hook also needs BPF LSM enabled.

Typical Debian/Ubuntu dependencies:

```bash
sudo apt install clang llvm bpftool libelf-dev zlib1g-dev pkg-config
```

Generate the CO-RE header and build:

```bash
make bootstrap
cargo build --release
```

`src/bpf/vmlinux.h` is generated from the running kernel and is not committed.

Run:

```bash
sudo ./target/release/kernel-sentinel --policy policies/default.yaml
```

Print every normalized event:

```bash
sudo ./target/release/kernel-sentinel --verbose-events
```

JSON detections are emitted one per line, which makes it easy to pipe the agent into `jq` or another collector.

## Rules

Rules are deliberately small while the event schema settles:

```yaml
- id: KS-WEB-001
  name: Web server spawned a shell
  severity: critical
  score: 95
  match:
    event: exec
    parent_comm: nginx
    executable_suffix: /sh
```

The next meaningful step is bounded sequence state so related events can be evaluated as one chain rather than independent matches.

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
- rules are single-event matches;
- kernel integration tests still need a dedicated VM matrix.

## License

Apache-2.0 for userspace code. The BPF object declares a GPL-compatible license.
