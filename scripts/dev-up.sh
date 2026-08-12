#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$ROOT_DIR/.run"
LOG_DIR="$ROOT_DIR/.logs"

mkdir -p "$RUN_DIR" "$LOG_DIR"

load_env_file() {
  local env_file="$1"
  if [[ -f "$env_file" ]]; then
    echo "Loading env from $env_file"
    set -a
    source "$env_file"
    set +a
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd npm
require_cmd curl
require_cmd python3

load_env_file "$ROOT_DIR/.env"
load_env_file "$ROOT_DIR/.env.local"

ensure_node_dependencies() {
  if [[ ! -d "$ROOT_DIR/node_modules" ]]; then
    echo "Installing Node.js dependencies..."
    (cd "$ROOT_DIR" && npm install)
  fi
}

ensure_agent_venv() {
  local agent_dir="$ROOT_DIR/services/agent-service"
  local recreate_venv="false"

  if [[ -d "$agent_dir/.venv" ]]; then
    local venv_python_version
    venv_python_version="$("$agent_dir/.venv/bin/python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")"
    if [[ "$(printf '%s\n' "3.10" "$venv_python_version" | sort -V | head -n1)" != "3.10" ]]; then
      echo "Recreating agent-service virtualenv because Python $venv_python_version is below 3.10..."
      rm -rf "$agent_dir/.venv"
      recreate_venv="true"
    fi
  fi

  if [[ ! -d "$agent_dir/.venv" ]]; then
    echo "Creating agent-service virtualenv..."
    python3 -m venv "$agent_dir/.venv"
  fi

  if ! (
    cd "$agent_dir" &&
      source .venv/bin/activate &&
      python -c "import fastapi, google.adk" >/dev/null 2>&1
  ); then
    echo "Installing agent-service Python dependencies..."
    (
      cd "$agent_dir" &&
        source .venv/bin/activate &&
        python -m pip install --upgrade pip &&
        pip install -e .
    )
  fi
}

is_pid_alive() {
  local pid="$1"
  kill -0 "$pid" >/dev/null 2>&1
}

is_port_listening() {
  local port="$1"
  lsof -iTCP:"$port" -sTCP:LISTEN -n -P >/dev/null 2>&1
}

start_service() {
  local name="$1"
  local port="$2"
  local health_url="$3"
  local command="$4"

  local pid_file="$RUN_DIR/$name.pid"
  local log_file="$LOG_DIR/$name.log"

  if [[ -f "$pid_file" ]]; then
    local existing_pid
    existing_pid="$(cat "$pid_file")"
    if is_pid_alive "$existing_pid"; then
      echo "$name is already running (pid $existing_pid)"
      return
    fi
    rm -f "$pid_file"
  fi

  if is_port_listening "$port"; then
    echo "Port $port is already in use; skipping $name" >&2
    return
  fi

  echo "Starting $name on port $port..."
  (
    cd "$ROOT_DIR"
    nohup bash -lc "$command" >"$log_file" 2>&1 &
    echo $! >"$pid_file"
  )

  for _ in {1..30}; do
    if curl -fsS "$health_url" >/dev/null 2>&1; then
      echo "$name is ready"
      return
    fi
    sleep 1
  done

  echo "$name failed to become ready. Check $log_file" >&2
  exit 1
}

ensure_node_dependencies
ensure_agent_venv

start_service \
  "event-service" \
  "4101" \
  "http://localhost:4101/health" \
  "cd '$ROOT_DIR' && npm run dev --workspace @safr-x-atp-demo/event-service"

start_service \
  "archive-service" \
  "4102" \
  "http://localhost:4102/health" \
  "cd '$ROOT_DIR' && npm run dev --workspace @safr-x-atp-demo/archive-service"

start_service \
  "verifier" \
  "4103" \
  "http://localhost:4103/health" \
  "cd '$ROOT_DIR' && npm run dev --workspace @safr-x-atp-demo/verifier"

start_service \
  "mcp-bank" \
  "4104" \
  "http://localhost:4104/health" \
  "cd '$ROOT_DIR' && FRONTEND_ORIGIN='http://localhost:4173' npm run dev --workspace @safr-x-atp-demo/mcp-bank"

start_service \
  "identity-service" \
  "4105" \
  "http://localhost:4105/health" \
  "cd '$ROOT_DIR' && WEBAUTHN_ORIGIN='http://localhost:4173' BANK_SERVICE_URL='http://localhost:4104' npm run dev --workspace @safr-x-atp-demo/identity-service"

start_service \
  "agent-service" \
  "4106" \
  "http://localhost:4106/health" \
  "cd '$ROOT_DIR/services/agent-service' && source .venv/bin/activate && unset GEMINI_API_KEY GOOGLE_API_KEY && GOOGLE_GENAI_USE_VERTEXAI='true' uvicorn app.main:app --host 0.0.0.0 --port 4106"

start_service \
  "frontend" \
  "4173" \
  "http://localhost:4173" \
  "cd '$ROOT_DIR' && npm run dev --workspace @safr-x-atp-demo/frontend -- --host 127.0.0.1 --port 4173"

echo
echo "All services are up."
echo "Frontend: http://localhost:4173"
echo "Logs: $LOG_DIR"
