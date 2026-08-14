#!/usr/bin/env bash
set -euo pipefail

status() {
  if command -v "$1" >/dev/null 2>&1; then
    printf '[ok]   %s\n' "$1"
  else
    printf '[info] %s is not installed\n' "$1"
  fi
}

echo 'Cortex prerequisites:'
status go

echo
printf 'Kernel sensor prerequisites (%s):\n' "$(uname -s 2>/dev/null || echo unknown)"
if [ "$(uname -s 2>/dev/null || true)" != "Linux" ]; then
  echo '[info] live eBPF sensor requires Linux; Cortex replay mode is still supported'
else
  status cargo
  status rustc
  status clang
  status bpftool
  status pkg-config
  if [ -r /sys/kernel/btf/vmlinux ]; then
    echo '[ok]   /sys/kernel/btf/vmlinux'
  else
    echo '[info] /sys/kernel/btf/vmlinux is unavailable; live sensor build cannot bootstrap here'
  fi
fi

echo
echo 'doctor is informational: make demo requires Go; make release requires the Linux sensor toolchain.'
