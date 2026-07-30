#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$ROOT_DIR/.run"
MANAGED_PORTS=(4101 4102 4103 4104 4105 4106 4173)

if [[ ! -d "$RUN_DIR" ]]; then
  echo "No running services found."
  exit 0
fi

is_pid_alive() {
  local pid="$1"
  kill -0 "$pid" >/dev/null 2>&1
}

for pid_file in "$RUN_DIR"/*.pid; do
  [[ -e "$pid_file" ]] || continue

  service_name="$(basename "$pid_file" .pid)"
  pid="$(cat "$pid_file")"

  if is_pid_alive "$pid"; then
    echo "Stopping $service_name (pid $pid)..."
    kill "$pid" >/dev/null 2>&1 || true

    for _ in {1..10}; do
      if ! is_pid_alive "$pid"; then
        break
      fi
      sleep 1
    done

    if is_pid_alive "$pid"; then
      echo "Force stopping $service_name (pid $pid)..."
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
  else
    echo "$service_name is not running, removing stale pid file."
  fi

  rm -f "$pid_file"
done

for port in "${MANAGED_PORTS[@]}"; do
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    if is_pid_alive "$pid"; then
      echo "Stopping listener on port $port (pid $pid)..."
      kill "$pid" >/dev/null 2>&1 || true
      for _ in {1..10}; do
        if ! is_pid_alive "$pid"; then
          break
        fi
        sleep 1
      done
      if is_pid_alive "$pid"; then
        echo "Force stopping listener on port $port (pid $pid)..."
        kill -9 "$pid" >/dev/null 2>&1 || true
      fi
    fi
  done < <(lsof -t -iTCP:"$port" -sTCP:LISTEN -n -P 2>/dev/null | sort -u)
done

echo "All managed services have been stopped."
