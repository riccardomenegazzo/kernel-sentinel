#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v go >/dev/null 2>&1; then
  echo "missing dependency: go (1.22+)" >&2
  exit 1
fi

echo "==> testing Sentinel Cortex"
(cd "$ROOT/cortex" && go test ./...)

echo
echo "==> replaying deterministic incident"
(cd "$ROOT/cortex" && go run ./cmd/cortex \
  --detections testdata/web-compromise.jsonl \
  --service workspace-runtime \
  --slo-target 0.999 \
  --good 99850 \
  --total 100000 \
  --window 30d)
