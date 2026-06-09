#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${ROOT_DIR}/.tmp/e2e"
PID_FILE="${STATE_DIR}/server.pid"
LOG_FILE="${STATE_DIR}/server.log"
BIND_ADDR="127.0.0.1:8080"
BASE_URL="http://${BIND_ADDR}"
DB_URL="postgres://user:password@127.0.0.1:5432/lnurl"
LNURL_BIN="${LNURL_BIN:-${ROOT_DIR}/target/debug/lnurl}"

mkdir -p "${STATE_DIR}"

stop_existing() {
  if [ ! -f "${PID_FILE}" ]; then
    return 0
  fi

  local existing_pid
  existing_pid="$(<"${PID_FILE}")"
  if [ -n "${existing_pid}" ] && kill -0 "${existing_pid}" 2>/dev/null; then
    kill "${existing_pid}" 2>/dev/null || true
    for _ in $(seq 1 10); do
      if ! kill -0 "${existing_pid}" 2>/dev/null; then
        break
      fi
      sleep 1
    done
  fi
  rm -f "${PID_FILE}"
}

wait_for_url() {
  local url="${1:?url is required}"
  local deadline=$((SECONDS + 300))
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

cd "${ROOT_DIR}"
docker compose up -d postgres
stop_existing
: >"${LOG_FILE}"

if [ ! -x "${LNURL_BIN}" ]; then
  cargo build --locked --bin lnurl
fi

BREEZ_LNURL_SSP_AUTH_SEED="${BREEZ_LNURL_SSP_AUTH_SEED:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}" \
  "${LNURL_BIN}" \
    --address "${BIND_ADDR}" \
    --auto-migrate \
    --db-url "${DB_URL}" \
    --domains "localhost:8080,127.0.0.1:8080" \
    --log-level "info" \
    --network "regtest" \
    --scheme "http" \
    >"${LOG_FILE}" 2>&1 &

server_pid=$!
echo "${server_pid}" >"${PID_FILE}"

if ! wait_for_url "${BASE_URL}/health"; then
  echo "server did not become ready at ${BASE_URL}/health; see ${LOG_FILE}" >&2
  stop_existing
  exit 1
fi

echo "server ready at ${BASE_URL} (pid ${server_pid})"
