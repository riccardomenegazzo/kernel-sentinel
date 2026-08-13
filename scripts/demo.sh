#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
Start the agent in another terminal:
  sudo ./target/release/kernel-sentinel --verbose-events

Then generate a couple of ordinary test events:
  sudo cat /etc/shadow >/dev/null
  cp /bin/true /tmp/ks-demo
  /tmp/ks-demo
EOF
