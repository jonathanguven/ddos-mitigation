#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if command -v tmux >/dev/null 2>&1; then
  exec "$ROOT_DIR/scripts/start_tmux.sh"
fi

cat <<EOF
tmux is not installed, so start these commands in separate terminals:

1. ryu-manager --ofp-tcp-listen-port 6653 ryu_app/ids_controller.py
2. sudo python3 mininet/topology.py
3. cd backend && uvicorn main:app --reload --host 0.0.0.0 --port 8000
4. cd frontend && npm install && npm run dev -- --host 0.0.0.0

Frontend: http://localhost:5173
Backend:  http://localhost:8000/api/health
EOF
