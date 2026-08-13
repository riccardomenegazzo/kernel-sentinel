# Kernel hook choices

The current backend uses stable tracepoints for process lifecycle events and an LSM file hook for path-aware file telemetry.

## Execution

`sched_process_exec` is used for successful image replacement. A syscall entry hook would capture intent, not successful execution, and would need separate handling for every exec variant.

## Fork and exit

`sched_process_fork` and `sched_process_exit` provide enough information to maintain the userspace process ancestry table without depending on internal kernel function names.

## Credentials

The first credential event records `setuid(2)` attempts. The requested UID is kept separate from the current effective credentials. A committed-credential event should be added later so attempted and successful transitions can be distinguished.

## File access

The file-open hook runs at the LSM layer and gives the probe an actual `struct file`. Path resolution uses a sleepable LSM attachment because `bpf_d_path` is restricted to that context.

## Compatibility

The BPF backend depends on BTF and BPF LSM for the file hook. Capability probing and an audit-only fallback are still planned for older or differently configured kernels.
