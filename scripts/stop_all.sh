#!/usr/bin/env bash
set -euo pipefail

SESSION="${SESSION:-sdn-ddos-demo}"

pkill -f "ryu-manager.*ids_controller.py" 2>/dev/null || true
pkill -f "uvicorn main:app" 2>/dev/null || true
pkill -f "vite.*--host" 2>/dev/null || true
pkill -f "npm run dev" 2>/dev/null || true
pkill -f "mininet/topology.py" 2>/dev/null || true
pkill -f "iperf" 2>/dev/null || true
pkill -f "ping -i 0.5 10.0.0.5" 2>/dev/null || true

if command -v tmux >/dev/null 2>&1; then
  tmux kill-session -t "$SESSION" 2>/dev/null || true
fi

if command -v mn >/dev/null 2>&1; then
  sudo mn -c || true
fi

echo "Stopped demo processes and cleaned Mininet state where available."
