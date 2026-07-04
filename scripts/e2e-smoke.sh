#!/usr/bin/env bash
# Phase 9 AC6: end-to-end smoke harness. Builds and runs the agent against
# a temporary data dir on the host, then runs the smoke binary against its
# loopback WebSocket. Fails-blocks merge when wired into CI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="$(mktemp -d)"
trap 'rm -rf "$DATA_DIR"; [[ -n "${AGENT_PID:-}" ]] && kill "$AGENT_PID" 2>/dev/null || true' EXIT

PORT="${PORT:-7676}"

echo "[smoke] building agent + smoke binaries"
(cd "$ROOT" && go build -o "$DATA_DIR/rootmote-agent" ./cmd/rootmote-agent)
(cd "$ROOT" && go build -o "$DATA_DIR/rootmote-e2e-smoke" ./cmd/e2e-smoke)

echo "[smoke] starting agent (data-dir=$DATA_DIR, addr=127.0.0.1:$PORT)"
"$DATA_DIR/rootmote-agent" \
  --addr "127.0.0.1:$PORT" \
  --data-dir "$DATA_DIR/state" \
  >"$DATA_DIR/agent.log" 2>&1 &
AGENT_PID=$!

# Wait for the agent to start accepting connections.
for i in {1..40}; do
  if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
    break
  fi
  sleep 0.25
done
if ! kill -0 "$AGENT_PID" 2>/dev/null; then
  echo "[smoke] agent died at startup:"
  cat "$DATA_DIR/agent.log"
  exit 1
fi

echo "[smoke] running e2e-smoke against ws://127.0.0.1:$PORT/ws"
"$DATA_DIR/rootmote-e2e-smoke" \
  -ws "ws://127.0.0.1:$PORT/ws" \
  -workspace-root "$DATA_DIR/state/projects"

echo "[smoke] OK"
