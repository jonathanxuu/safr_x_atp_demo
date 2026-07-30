#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$ROOT_DIR/.run"

services=(
  "event-service:4101:http://localhost:4101/health"
  "archive-service:4102:http://localhost:4102/health"
  "verifier:4103:http://localhost:4103/health"
  "mcp-bank:4104:http://localhost:4104/health"
  "identity-service:4105:http://localhost:4105/health"
  "agent-service:4106:http://localhost:4106/health"
  "frontend:4173:http://localhost:4173"
)

is_pid_alive() {
  local pid="$1"
  kill -0 "$pid" >/dev/null 2>&1
}

is_port_listening() {
  local port="$1"
  lsof -iTCP:"$port" -sTCP:LISTEN -n -P >/dev/null 2>&1
}

printf "%-18s %-8s %-12s %-10s %s\n" "SERVICE" "PORT" "PID" "HEALTH" "NOTES"

for service in "${services[@]}"; do
  IFS=":" read -r name port health_url <<<"$service"
  pid_file="$RUN_DIR/$name.pid"
  pid_value="-"
  notes=""
  health_state="down"

  if [[ -f "$pid_file" ]]; then
    candidate_pid="$(cat "$pid_file")"
    if is_pid_alive "$candidate_pid"; then
      pid_value="$candidate_pid"
    else
      pid_value="stale"
      notes="remove $pid_file"
    fi
  fi

  if curl -fsS "$health_url" >/dev/null 2>&1; then
    health_state="ok"
  elif is_port_listening "$port"; then
    health_state="port-up"
    if [[ -z "$notes" ]]; then
      notes="port occupied"
    fi
  fi

  printf "%-18s %-8s %-12s %-10s %s\n" "$name" "$port" "$pid_value" "$health_state" "$notes"
done
