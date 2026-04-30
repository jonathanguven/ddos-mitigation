#!/usr/bin/env bash
set -euo pipefail

curl -fsS -X POST http://localhost:8000/api/reset >/dev/null 2>&1 || true

if command -v ovs-ofctl >/dev/null 2>&1; then
  ovs-ofctl -O OpenFlow13 del-flows s1 \
    "priority=100,ip,nw_src=10.0.0.1,nw_dst=10.0.0.5" 2>/dev/null || \
  sudo -n ovs-ofctl -O OpenFlow13 del-flows s1 \
    "priority=100,ip,nw_src=10.0.0.1,nw_dst=10.0.0.5" 2>/dev/null || true
fi

rm -f /tmp/h1_attack.log /tmp/h2_ping.log /tmp/h3_iperf.log /tmp/h4_iperf.log

echo "Demo reset requested."
