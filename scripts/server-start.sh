#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${LOG_DIR:-/tmp/safr_x_atp_demo_logs}"
RUN_DIR="${RUN_DIR:-$ROOT_DIR/.run}"

mkdir -p "$LOG_DIR" "$RUN_DIR"

if [[ ! -f "$ROOT_DIR/.env.server" ]]; then
  echo "Missing .env.server in $ROOT_DIR" >&2
  exit 1
fi

set -a
source "$ROOT_DIR/.env.server"
set +a

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

wait_health() {
  local name="$1"
  local url="$2"
  local log_file="$3"

  for _ in {1..40}; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "$name is ready"
      return 0
    fi
    sleep 1
  done

  echo "$name failed to become ready" >&2
  echo "Log file: $log_file" >&2
  tail -n 120 "$log_file" >&2 || true
  exit 1
}

start_node_service() {
  local name="$1"
  local workspace="$2"
  local health_url="$3"
  local log_file="$LOG_DIR/$name.log"
  local pid_file="$RUN_DIR/$name.pid"

  if [[ -f "$pid_file" ]]; then
    local existing_pid
    existing_pid="$(cat "$pid_file")"
    if kill -0 "$existing_pid" >/dev/null 2>&1; then
      echo "$name already running (pid $existing_pid)"
      return 0
    fi
    rm -f "$pid_file"
  fi

  echo "Starting $name..."
  (
    cd "$ROOT_DIR"
    nohup npm run dev --workspace "$workspace" >"$log_file" 2>&1 &
    echo $! >"$pid_file"
  )
  wait_health "$name" "$health_url" "$log_file"
}

start_agent_service() {
  local name="agent-service"
  local log_file="$LOG_DIR/$name.log"
  local pid_file="$RUN_DIR/$name.pid"

  if [[ -f "$pid_file" ]]; then
    local existing_pid
    existing_pid="$(cat "$pid_file")"
    if kill -0 "$existing_pid" >/dev/null 2>&1; then
      echo "$name already running (pid $existing_pid)"
      return 0
    fi
    rm -f "$pid_file"
  fi

  require_cmd uv

  echo "Preparing $name Python environment..."
  (
    cd "$ROOT_DIR/services/agent-service"
    uv sync
  )

  echo "Starting $name..."
  (
    cd "$ROOT_DIR/services/agent-service"
    nohup uv run uvicorn app.main:app --host 127.0.0.1 --port 4106 >"$log_file" 2>&1 &
    echo $! >"$pid_file"
  )
  wait_health "$name" "http://127.0.0.1:4106/health" "$log_file"
}

require_cmd npm
require_cmd curl
require_cmd python3

cd "$ROOT_DIR"

echo "Building workspaces..."
npm run build --workspaces --if-present

start_node_service "event-service" "@safr-x-atp-demo/event-service" "http://127.0.0.1:4101/health"
start_node_service "archive-service" "@safr-x-atp-demo/archive-service" "http://127.0.0.1:4102/health"
start_node_service "verifier" "@safr-x-atp-demo/verifier" "http://127.0.0.1:4103/health"
start_node_service "mcp-bank" "@safr-x-atp-demo/mcp-bank" "http://127.0.0.1:4104/health"
start_node_service "identity-service" "@safr-x-atp-demo/identity-service" "http://127.0.0.1:4105/health"
start_agent_service

echo
echo "All services are up."
echo "Logs: $LOG_DIR"
echo "PID files: $RUN_DIR"
