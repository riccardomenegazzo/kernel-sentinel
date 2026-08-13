# kernel-sentinel

Linux runtime monitoring experiments with Rust, eBPF CO-RE and BPF LSM.

The agent collects a small set of process and file events in the kernel, enriches them in userspace, keeps a process ancestry table, and evaluates YAML rules. There is also a deliberately narrow enforcement experiment using `bprm_check_security` for cgroup-scoped execution blocking.

This is still early work. I am using the repository to explore the boundary between tracing and runtime enforcement without turning the BPF side into a policy engine.

## Direction

The design keeps kernel work bounded and pushes enrichment, ancestry reconstruction and policy evaluation into Rust userspace. The kernel side is intended to provide compact event context and, only where explicitly configured, a small enforcement decision.

The first milestones are:

- exec/fork/exit telemetry
- credential transition attempts
- PID and mount namespace context
- cgroup/container context
- process ancestry reconstruction
- file-open auditing at the LSM layer
- YAML detection rules
- cgroup-scoped enforcement experiments

## Build

The project expects a recent Linux kernel with BTF available at `/sys/kernel/btf/vmlinux`. BPF LSM support is required for the LSM probes.

Typical Debian/Ubuntu dependencies:

```bash
sudo apt install clang llvm bpftool libelf-dev zlib1g-dev pkg-config
```

Generate `vmlinux.h` and build:

```bash
make bootstrap
cargo build --release
```

`src/bpf/vmlinux.h` is generated from the running kernel and is not committed.

## Notes

I am documenting hook choices and known limitations as the project evolves. In particular, successful process execution telemetry and pre-execution enforcement are treated as separate concerns: `sched_process_exec` is a useful observation point, while `bprm_check_security` is a security decision point.

The current roadmap is to get a small event pipeline working end-to-end first, then add stateful sequence detection and better container metadata resolution.

## License

Apache-2.0.
