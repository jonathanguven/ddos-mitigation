#!/usr/bin/env bash
set -euo pipefail

curl -fsS -X POST http://localhost:8000/api/reset >/dev/null 2>&1 || true

if command -v ovs-ofctl >/dev/null 2>&1; then
  ovs-ofctl -O OpenFlow13 del-flows s1 "priority=100,ip" 2>/dev/null || \
  sudo -n ovs-ofctl -O OpenFlow13 del-flows s1 "priority=100,ip" 2>/dev/null || true
  ovs-ofctl -O OpenFlow13 del-flows s1 "priority=90,ip" 2>/dev/null || \
  sudo -n ovs-ofctl -O OpenFlow13 del-flows s1 "priority=90,ip" 2>/dev/null || true
  ovs-ofctl -O OpenFlow13 del-meters s1 2>/dev/null || \
  sudo -n ovs-ofctl -O OpenFlow13 del-meters s1 2>/dev/null || true
fi

rm -f /tmp/h*_normal.log /tmp/h*_single_source_flood.log /tmp/h*_multi_source_flood.log

echo "Demo reset requested."
