# Next work

## Correctness

- distinguish attempted and committed credential transitions
- capture bounded exec arguments
- count dropped events
- handle PID reuse in the process table
- add integration tests across multiple kernels

## Rules

- support stateful event sequences
- add richer parent/child process conditions
- add namespace and file context to rule matching

## Containers

- resolve OCI runtime metadata
- attach Kubernetes workload metadata
- baseline host and workload namespaces
- select policies per workload

## Engineering

- capability probing
- metrics
- policy hot reload
- event schema versioning
- reproducible benchmarks
- fuzz event and policy decoders
