#!/usr/bin/env bash
set -euo pipefail

for bin in cargo rustc clang bpftool pkg-config; do
  command -v "$bin" >/dev/null || {
    echo "missing dependency: $bin" >&2
    exit 1
  }
done

test -r /sys/kernel/btf/vmlinux || {
  echo "kernel BTF unavailable: /sys/kernel/btf/vmlinux" >&2
  exit 1
}

bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
echo "generated src/bpf/vmlinux.h"
