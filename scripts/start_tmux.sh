#!/usr/bin/env bash
set -euo pipefail

SESSION="${SESSION:-sdn-ddos-demo}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required for this script. Use scripts/start_all.sh for manual commands."
  exit 1
fi

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "tmux session '$SESSION' already exists. Attaching..."
  exec tmux attach-session -t "$SESSION"
fi

tmux new-session -d -s "$SESSION" -c "$ROOT_DIR" \
  "ryu-manager --ofp-tcp-listen-port 6653 ryu_app/ids_controller.py"

tmux split-window -h -t "$SESSION:0" -c "$ROOT_DIR" \
  "sudo python3 mininet/topology.py"

tmux split-window -v -t "$SESSION:0.0" -c "$ROOT_DIR/backend" \
  "uvicorn main:app --reload --host 0.0.0.0 --port 8000"

tmux split-window -v -t "$SESSION:0.1" -c "$ROOT_DIR/frontend" \
  "npm install && npm run dev -- --host 0.0.0.0"

tmux select-layout -t "$SESSION:0" tiled >/dev/null
tmux set-option -t "$SESSION" remain-on-exit on >/dev/null

echo "Started tmux session '$SESSION'."
echo "Frontend: http://localhost:5173"
echo "Backend:  http://localhost:8000/api/health"
exec tmux attach-session -t "$SESSION"
