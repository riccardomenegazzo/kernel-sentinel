# Architecture

Kernel Sentinel is split across the kernel/userspace boundary. The kernel side emits compact events; Rust performs enrichment, ancestry tracking and rule evaluation.

```text
kernel hooks -> ring buffer -> Rust collector -> enrichment -> process graph -> rules -> output
```

The design keeps expensive or stateful work out of BPF programs. Process metadata, container inference and policy matching all stay in userspace.

## Principles

- prefer stable tracepoints for lifecycle telemetry;
- use security-semantic hooks when the distinction matters;
- keep event payloads fixed-size and bounded;
- make dropped events visible instead of silently ignoring overload;
- keep prevention opt-in and narrowly scoped;
- document hook trade-offs instead of hiding them behind wrappers.

## Event lifecycle

A BPF program fills a fixed-size event and submits it through a ring buffer. Userspace normalizes the record, enriches it from `/proc`, updates the ancestry table and evaluates zero or more rules. JSON output is newline-delimited so it can be piped into other tools.
