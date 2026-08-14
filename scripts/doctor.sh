#!/usr/bin/env bash
set -euo pipefail

fail=0

check_required() {
  if command -v "$1" >/dev/null 2>&1; then
    printf '[ok]   %s\n' "$1"
  else
    printf '[miss] %s\n' "$1"
    fail=1
  fi
}

check_optional() {
  if command -v "$1" >/dev/null 2>&1; then
    printf '[ok]   %s\n' "$1"
  else
    printf '[info] %s is not installed\n' "$1"
  fi
}

echo 'Cortex prerequisites:'
check_required go

echo
printf 'Kernel sensor prerequisites (%s):\n' "$(uname -s 2>/dev/null || echo unknown)"
if [ "$(uname -s 2>/dev/null || true)" != "Linux" ]; then
  echo '[info] live eBPF sensor requires Linux; Cortex replay mode is still supported'
else
  check_optional cargo
  check_optional rustc
  check_optional clang
  check_optional bpftool
  check_optional pkg-config
  if [ -r /sys/kernel/btf/vmlinux ]; then
    echo '[ok]   /sys/kernel/btf/vmlinux'
  else
    echo '[info] /sys/kernel/btf/vmlinux is unavailable; live sensor build cannot bootstrap here'
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo 'Install the missing Cortex prerequisite(s) before running make demo.' >&2
  exit 1
fi
