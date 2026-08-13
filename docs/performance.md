# Performance

Numbers belong here only after they are measured on a reproducible host.

## Metrics

- idle CPU overhead
- resident set size
- events per second
- queue/ring-buffer drops
- p50/p95/p99 event-to-userspace latency
- fork/exec workload slowdown

## Workloads

```bash
hyperfine 'for i in $(seq 1 1000); do /bin/true; done'
stress-ng --fork 8 --timeout 30s
docker run --rm nginx:alpine
```

Every result should include CPU model, kernel release, architecture, Rust compiler, clang/libbpf versions, policy file and the exact command used.
